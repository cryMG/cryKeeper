import math
import os
from collections import defaultdict
from pathlib import Path

from flask import (
  Blueprint,
  Response,
  current_app,
  make_response,
  redirect,
  render_template,
)
from prometheus_client import (
  CONTENT_TYPE_LATEST,
  CollectorRegistry,
  Counter,
  Histogram,
  generate_latest,
)
from prometheus_client.multiprocess import MultiProcessCollector

from .config import DEFAULT_FOOTER_HTML, INTERNAL_OBSERVABILITY_PATH

CRYKEEPER_PROMETHEUS_DIR_ENV = "CRYKEEPER_PROMETHEUS_MULTIPROC_DIR"
PROMETHEUS_DIR_ENV = "PROMETHEUS_MULTIPROC_DIR"

_LATENCY_BUCKETS = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0)

observability = Blueprint(
  "crykeeper_observability",
  __name__,
  static_folder="static",
  static_url_path="/static",
)


class CryKeeperObservability:
  """Own Prometheus metrics plus a small server-rendered operational snapshot."""

  def __init__(self) -> None:
    self._multiprocess_dir = _configure_prometheus_directory()
    self._registry = CollectorRegistry()
    self._check_requests = Counter(
      "crykeeper_check_requests",
      "Auth check outcomes seen by the nginx auth_request flow.",
      labelnames=("host", "outcome"),
      registry=self._registry,
    )
    self._auth_bypass = Counter(
      "crykeeper_auth_bypass",
      "Configured auth bypasses matched during GET /check.",
      labelnames=("host", "reason"),
      registry=self._registry,
    )
    self._challenge_requests = Counter(
      "crykeeper_challenge_requests",
      "Browser-facing challenge page outcomes.",
      labelnames=("host", "provider", "outcome"),
      registry=self._registry,
    )
    self._verify_attempts = Counter(
      "crykeeper_verify_attempts",
      "Verification outcomes grouped by host and provider.",
      labelnames=("host", "provider", "outcome", "reason"),
      registry=self._registry,
    )
    self._provider_requests = Counter(
      "crykeeper_provider_requests",
      "Provider-facing operations such as verify or ALTCHA challenge generation.",
      labelnames=("host", "provider", "operation", "outcome"),
      registry=self._registry,
    )
    self._provider_latency = Histogram(
      "crykeeper_provider_latency_seconds",
      "Latency of provider-facing operations.",
      labelnames=("host", "provider", "operation"),
      buckets=_LATENCY_BUCKETS,
      registry=self._registry,
    )
    self._verify_duration = Histogram(
      "crykeeper_verify_duration_seconds",
      "End-to-end duration of POST /verify requests after preliminary checks.",
      labelnames=("host", "provider", "outcome"),
      buckets=_LATENCY_BUCKETS,
      registry=self._registry,
    )
    self._rate_limit_hits = Counter(
      "crykeeper_rate_limit_hits",
      "Requests blocked by the challenge or verify rate limit.",
      labelnames=("host", "scope", "backend"),
      registry=self._registry,
    )
    self._rate_limit_backend_failures = Counter(
      "crykeeper_rate_limit_backend_failures",
      "Distributed rate-limit backend failures that triggered a local fallback.",
      labelnames=("backend",),
      registry=self._registry,
    )

  def record_check(self, host: str, outcome: str) -> None:
    """Count one auth_request outcome for the normalized host."""
    self._check_requests.labels(host=_metric_host(host), outcome=outcome).inc()

  def record_auth_bypass(self, host: str, reason: str) -> None:
    """Count one configured auth bypass match for the normalized host."""
    self._auth_bypass.labels(host=_metric_host(host), reason=reason).inc()

  def record_challenge(self, host: str, provider: str, outcome: str) -> None:
    """Count one browser-facing challenge outcome."""
    self._challenge_requests.labels(
      host=_metric_host(host),
      provider=(provider or "dummy").lower(),
      outcome=outcome,
    ).inc()

  def record_verify_result(
    self, host: str, provider: str, outcome: str, reason: str = "none"
  ) -> None:
    """Count one verify result labeled by provider, outcome, and reason."""
    self._verify_attempts.labels(
      host=_metric_host(host),
      provider=(provider or "dummy").lower(),
      outcome=outcome,
      reason=reason or "none",
    ).inc()

  def record_provider_result(
    self,
    host: str,
    provider: str,
    operation: str,
    outcome: str,
    duration_seconds: float,
  ) -> None:
    """Record provider request totals together with their latency."""
    metric_host = _metric_host(host)
    metric_provider = (provider or "dummy").lower()
    self._provider_requests.labels(
      host=metric_host,
      provider=metric_provider,
      operation=operation,
      outcome=outcome,
    ).inc()
    self._provider_latency.labels(
      host=metric_host,
      provider=metric_provider,
      operation=operation,
    ).observe(max(duration_seconds, 0.0))

  def record_verify_duration(
    self, host: str, provider: str, outcome: str, duration_seconds: float
  ) -> None:
    """Observe one end-to-end verify request duration."""
    self._verify_duration.labels(
      host=_metric_host(host),
      provider=(provider or "dummy").lower(),
      outcome=outcome,
    ).observe(max(duration_seconds, 0.0))

  def record_rate_limit_hit(self, host: str, scope: str, backend: str) -> None:
    """Count one request blocked by the configured rate limiter."""
    self._rate_limit_hits.labels(
      host=_metric_host(host),
      scope=scope,
      backend=backend,
    ).inc()

  def record_rate_limit_backend_failure(self, backend: str) -> None:
    """Count one distributed backend failure before the limiter falls back locally."""
    self._rate_limit_backend_failures.labels(backend=backend).inc()

  def render_metrics(self) -> bytes:
    """Render the Prometheus exposition payload for the current registry."""
    return generate_latest(self._collector_registry())

  def dashboard_snapshot(self) -> dict[str, object]:
    """Build the server-rendered dashboard view model from live samples."""
    samples = _sample_index(self._collector_registry())
    verify_totals = _verify_totals(samples)
    verify_success = verify_totals["success"]
    verify_total = verify_totals["total"]
    skip_route_bypasses = _sum_labeled_samples(
      samples,
      "crykeeper_auth_bypass_total",
      reason="skip_route",
    )
    rate_limit_hits = _sum_samples(samples, "crykeeper_rate_limit_hits_total")
    backend_failures = _sum_samples(
      samples, "crykeeper_rate_limit_backend_failures_total"
    )

    cards = (
      {
        "key": "check_requests",
        "title": "Check requests",
        "value": _format_integer(
          _sum_samples(samples, "crykeeper_check_requests_total")
        ),
        "detail": "Bypasses, valid cookies, and challenge redirects since startup.",
      },
      {
        "key": "verify_success_rate",
        "title": "Verify success rate",
        "value": _format_rate(verify_success, verify_total),
        "detail": f"{_format_integer(verify_success)} successful verifies out of {_format_integer(verify_total)}.",
      },
      {
        "key": "skip_routes",
        "title": "Skip routes",
        "value": _format_integer(skip_route_bypasses),
        "detail": "Requests bypassed by configured skip_routes since startup.",
      },
      {
        "key": "rate_limit_hits",
        "title": "Rate limit hits",
        "value": _format_integer(rate_limit_hits),
        "detail": "Blocked challenge or verify requests since startup.",
      },
      {
        "key": "backend_fallbacks",
        "title": "Backend fallbacks",
        "value": _format_integer(backend_failures),
        "detail": "Valkey backend failures that fell back to in-memory checks.",
      },
    )

    return {
      "cards": cards,
      "verify_rows": _verify_rows(samples),
      "latency_rows": _provider_latency_rows(samples),
      "rate_limit_rows": _rate_limit_rows(samples),
      "backend_failure_rows": _backend_failure_rows(samples),
      "metrics_path": f"{INTERNAL_OBSERVABILITY_PATH}/metrics",
      "dashboard_path": f"{INTERNAL_OBSERVABILITY_PATH}/dashboard",
    }

  def _collector_registry(self) -> CollectorRegistry:
    """Return a registry that aggregates all workers when multiprocess mode is enabled."""
    if not self._multiprocess_dir:
      return self._registry

    registry = CollectorRegistry()
    MultiProcessCollector(registry)
    return registry


@observability.get("/")
def observability_index() -> Response:
  """Redirect the fixed internal prefix root to the dashboard page."""
  return redirect(f"{INTERNAL_OBSERVABILITY_PATH}/dashboard")


@observability.get("/dashboard")
def dashboard() -> Response:
  """Render the internal observability dashboard."""
  snapshot = current_app.extensions["crykeeper_observability"].dashboard_snapshot()
  response = make_response(
    render_template(
      "dashboard.html",
      footer_html=DEFAULT_FOOTER_HTML,
      snapshot=snapshot,
    )
  )
  return _with_observability_headers(response, content_type=None)


@observability.get("/metrics")
def metrics() -> Response:
  """Serve the Prometheus metrics exposition for internal scraping."""
  payload = current_app.extensions["crykeeper_observability"].render_metrics()
  response = Response(payload, mimetype=CONTENT_TYPE_LATEST)
  return _with_observability_headers(response, content_type=CONTENT_TYPE_LATEST)


def _with_observability_headers(
  response: Response, content_type: str | None
) -> Response:
  """Apply the shared cache and hardening headers for observability responses."""
  response.headers["Cache-Control"] = "no-store"
  response.headers["Pragma"] = "no-cache"
  response.headers["Referrer-Policy"] = "same-origin"
  response.headers["X-Content-Type-Options"] = "nosniff"
  response.headers["X-Frame-Options"] = "DENY"
  response.headers["X-Robots-Tag"] = "noindex, nofollow"
  if content_type is not None:
    response.headers["Content-Type"] = content_type
  return response


def _configure_prometheus_directory() -> str | None:
  """Prepare and export the multiprocess directory when aggregation is enabled."""
  raw_directory = (
    os.getenv(CRYKEEPER_PROMETHEUS_DIR_ENV) or os.getenv(PROMETHEUS_DIR_ENV) or ""
  ).strip()
  if not raw_directory:
    return None

  directory = Path(raw_directory).expanduser()
  try:
    directory.mkdir(parents=True, exist_ok=True)
  except OSError as exc:
    raise RuntimeError(
      f"Failed to prepare Prometheus multiprocess directory {directory}: {exc}"
    ) from exc

  os.environ[PROMETHEUS_DIR_ENV] = str(directory)
  return str(directory)


def _metric_host(host: str | None) -> str:
  """Collapse missing or blank hostnames into one stable metrics label."""
  return (host or "default").strip() or "default"


def _sample_index(registry: CollectorRegistry) -> dict[str, list[object]]:
  """Group collected Prometheus samples by sample name for dashboard lookups."""
  index: dict[str, list[object]] = defaultdict(list)
  for metric in registry.collect():
    for sample in metric.samples:
      index[sample.name].append(sample)
  return index


def _sum_samples(samples: dict[str, list[object]], name: str) -> float:
  """Sum all sample values for one Prometheus sample name."""
  return sum(sample.value for sample in samples.get(name, ()))


def _sum_labeled_samples(
  samples: dict[str, list[object]], name: str, **labels: str
) -> float:
  """Sum all samples for one metric name that match the requested label set."""
  return sum(
    sample.value
    for sample in samples.get(name, ())
    if all(sample.labels.get(key) == value for key, value in labels.items())
  )


def _verify_totals(samples: dict[str, list[object]]) -> dict[str, float]:
  """Return total and successful verify counts across all hosts and providers."""
  result = {"success": 0.0, "total": 0.0}
  for sample in samples.get("crykeeper_verify_attempts_total", ()):
    result["total"] += sample.value
    if sample.labels.get("outcome") == "success":
      result["success"] += sample.value
  return result


def _verify_rows(samples: dict[str, list[object]]) -> list[dict[str, str]]:
  """Build per-host and per-provider verify summary rows for the dashboard."""
  grouped: dict[tuple[str, str], dict[str, object]] = {}
  for sample in samples.get("crykeeper_verify_attempts_total", ()):
    labels = sample.labels
    key = (labels.get("host", "default"), labels.get("provider", "dummy"))
    row = grouped.setdefault(
      key,
      {
        "host": key[0],
        "provider": key[1],
        "success": 0.0,
        "total": 0.0,
        "reasons": defaultdict(float),
      },
    )
    row["total"] += sample.value
    if labels.get("outcome") == "success":
      row["success"] += sample.value
      continue

    reason = labels.get("reason", "unknown")
    row["reasons"][reason] += sample.value

  rows: list[dict[str, str]] = []
  for row in grouped.values():
    reasons = row["reasons"]
    failure_detail = "none"
    if reasons:
      failure_detail = ", ".join(
        f"{reason} {_format_integer(count)}"
        for reason, count in sorted(
          reasons.items(), key=lambda item: (-item[1], item[0])
        )
      )
    rows.append(
      {
        "host": row["host"],
        "provider": row["provider"],
        "success_rate": _format_rate(row["success"], row["total"]),
        "successful": _format_integer(row["success"]),
        "total": _format_integer(row["total"]),
        "failures": failure_detail,
      }
    )

  return sorted(rows, key=lambda item: (item["host"], item["provider"]))


def _provider_latency_rows(samples: dict[str, list[object]]) -> list[dict[str, str]]:
  """Build provider latency rows from Prometheus histogram samples."""
  histogram = _histogram_snapshot(samples, "crykeeper_provider_latency_seconds")
  rows: list[dict[str, str]] = []
  for key, values in histogram.items():
    labels = dict(key)
    count = values.get("count", 0.0)
    rows.append(
      {
        "host": labels.get("host", "default"),
        "provider": labels.get("provider", "dummy"),
        "operation": labels.get("operation", "verify"),
        "count": _format_integer(count),
        "p95": _format_duration(values.get("p95")),
        "average": _format_duration(values.get("average")),
      }
    )

  return sorted(
    rows, key=lambda item: (item["host"], item["provider"], item["operation"])
  )


def _rate_limit_rows(samples: dict[str, list[object]]) -> list[dict[str, str]]:
  """Build one dashboard row per host, scope, and backend hit counter."""
  rows = [
    {
      "host": sample.labels.get("host", "default"),
      "scope": sample.labels.get("scope", "challenge"),
      "backend": sample.labels.get("backend", "memory"),
      "hits": _format_integer(sample.value),
    }
    for sample in samples.get("crykeeper_rate_limit_hits_total", ())
  ]
  return sorted(rows, key=lambda item: (item["host"], item["scope"], item["backend"]))


def _backend_failure_rows(samples: dict[str, list[object]]) -> list[dict[str, str]]:
  """Build one dashboard row per rate-limit backend failure source."""
  rows = [
    {
      "backend": sample.labels.get("backend", "valkey"),
      "count": _format_integer(sample.value),
    }
    for sample in samples.get("crykeeper_rate_limit_backend_failures_total", ())
  ]
  return sorted(rows, key=lambda item: item["backend"])


def _histogram_snapshot(
  samples: dict[str, list[object]], base_name: str
) -> dict[tuple[tuple[str, str], ...], dict[str, float]]:
  """Extract count, average, and p95 approximations from histogram samples."""
  buckets: dict[tuple[tuple[str, str], ...], list[tuple[float, float]]] = defaultdict(
    list
  )
  sums: dict[tuple[tuple[str, str], ...], float] = {}
  counts: dict[tuple[tuple[str, str], ...], float] = {}

  for sample in samples.get(f"{base_name}_bucket", ()):
    key = tuple(
      sorted((name, value) for name, value in sample.labels.items() if name != "le")
    )
    upper_bound = (
      math.inf if sample.labels.get("le") == "+Inf" else float(sample.labels["le"])
    )
    buckets[key].append((upper_bound, float(sample.value)))

  for sample in samples.get(f"{base_name}_sum", ()):
    key = tuple(sorted(sample.labels.items()))
    sums[key] = float(sample.value)

  for sample in samples.get(f"{base_name}_count", ()):
    key = tuple(sorted(sample.labels.items()))
    counts[key] = float(sample.value)

  snapshot: dict[tuple[tuple[str, str], ...], dict[str, float]] = {}
  for key, bucket_values in buckets.items():
    count = counts.get(key, 0.0)
    total = sums.get(key, 0.0)
    snapshot[key] = {
      "count": count,
      "average": (total / count) if count else math.nan,
      "p95": _histogram_quantile(0.95, bucket_values),
    }

  return snapshot


def _histogram_quantile(
  quantile: float, bucket_values: list[tuple[float, float]]
) -> float:
  """Approximate one histogram quantile from cumulative Prometheus buckets."""
  if not bucket_values:
    return math.nan

  ordered_buckets = sorted(bucket_values, key=lambda item: item[0])
  total_count = ordered_buckets[-1][1]
  if total_count <= 0:
    return math.nan

  wanted = quantile * total_count
  previous_count = 0.0
  previous_upper = 0.0
  for upper_bound, cumulative_count in ordered_buckets:
    if cumulative_count < wanted:
      previous_count = cumulative_count
      if math.isfinite(upper_bound):
        previous_upper = upper_bound
      continue

    bucket_count = cumulative_count - previous_count
    if bucket_count <= 0:
      return previous_upper
    if not math.isfinite(upper_bound):
      return previous_upper

    position = (wanted - previous_count) / bucket_count
    return previous_upper + ((upper_bound - previous_upper) * position)

  return previous_upper


def _format_integer(value: float) -> str:
  """Format one numeric dashboard counter without decimals."""
  return f"{int(value):,}"


def _format_rate(success: float, total: float) -> str:
  """Format one success ratio as a percentage when a denominator exists."""
  if total <= 0:
    return "n/a"
  return f"{(success / total) * 100:.1f}%"


def _format_duration(value: float) -> str:
  """Format one duration value in milliseconds or seconds for the dashboard."""
  if math.isnan(value):
    return "n/a"
  milliseconds = value * 1000
  if milliseconds >= 1000:
    return f"{value:.2f} s"
  if milliseconds >= 100:
    return f"{milliseconds:.0f} ms"
  if milliseconds >= 10:
    return f"{milliseconds:.1f} ms"
  return f"{milliseconds:.2f} ms"
