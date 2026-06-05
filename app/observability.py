import math
import os
from collections import defaultdict
from http import HTTPStatus
from pathlib import Path

from flask import (
  Blueprint,
  Response,
  current_app,
  make_response,
  redirect,
  render_template,
  request,
  url_for,
)
from prometheus_client import (
  CONTENT_TYPE_LATEST,
  CollectorRegistry,
  Counter,
  Histogram,
  generate_latest,
)
from prometheus_client.multiprocess import MultiProcessCollector

from .assets import hashed_asset_cache_control, resolved_asset_name
from .config import DEFAULT_FOOTER_HTML, INTERNAL_OBSERVABILITY_PATH

CRYKEEPER_PROMETHEUS_DIR_ENV = "CRYKEEPER_PROMETHEUS_MULTIPROC_DIR"
PROMETHEUS_DIR_ENV = "PROMETHEUS_MULTIPROC_DIR"

_LATENCY_BUCKETS = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0)
_READINESS_STATUS_ORDER = {"fail": 0, "warn": 1}

observability = Blueprint(
  "crykeeper_observability",
  __name__,
  static_folder="static",
  static_url_path="/static",
)


@observability.after_request
def _apply_hashed_asset_cache_headers(response: Response) -> Response:
  """Cache build-time hashed observability assets aggressively without caching HTML."""
  if request.endpoint != "crykeeper_observability.static":
    return response

  cache_control = hashed_asset_cache_control((request.view_args or {}).get("filename"))
  if cache_control is not None:
    response.headers["Cache-Control"] = cache_control
  return response


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
    self._unsolved_challenge_attempts = Counter(
      "crykeeper_unsolved_challenge_attempts",
      "Explicit challenge attempts that ended without a successful verification.",
      labelnames=("host", "provider", "reason"),
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
    self._request_header_issues = Counter(
      "crykeeper_request_header_issues",
      "Missing reverse-proxy forwarding headers detected on incoming requests.",
      labelnames=("host", "endpoint", "header"),
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

  def record_unsolved_challenge(self, host: str, provider: str, reason: str) -> None:
    """Count one explicit challenge attempt that did not end in success."""
    self._unsolved_challenge_attempts.labels(
      host=_metric_host(host),
      provider=(provider or "dummy").lower(),
      reason=reason or "unknown",
    ).inc()

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

  def record_request_header_issue(
    self,
    host: str,
    endpoint: str,
    header_name: str,
  ) -> None:
    """Count one request that reached the app without an expected proxy header."""
    self._request_header_issues.labels(
      host=_metric_host(host),
      endpoint=endpoint,
      header=header_name,
    ).inc()

  def render_metrics(self) -> bytes:
    """Render the Prometheus exposition payload for the current registry."""
    return generate_latest(self._collector_registry())

  def dashboard_snapshot(self) -> dict[str, object]:
    """Build the server-rendered dashboard view model from live samples."""
    samples = _sample_index(self._collector_registry())
    checks_allowed = _sum_labeled_samples(
      samples, "crykeeper_check_requests_total", outcome="allowed"
    )
    checks_challenge_required = _sum_labeled_samples(
      samples, "crykeeper_check_requests_total", outcome="challenge_required"
    )
    verify_totals = _verify_totals(samples)
    verify_success = verify_totals["success"]
    verify_total = verify_totals["total"]
    skip_route_bypasses = _sum_labeled_samples(
      samples,
      "crykeeper_auth_bypass_total",
      reason="skip_route",
    )
    rendered_challenges = _sum_labeled_samples(
      samples,
      "crykeeper_challenge_requests_total",
      outcome="rendered",
    )
    unsolved_challenges = _sum_samples(
      samples, "crykeeper_unsolved_challenge_attempts_total"
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
        "key": "checks_allowed",
        "title": "Checks allowed",
        "value": _format_integer(checks_allowed),
        "detail": "Allowed check requests without challenge since startup.",
      },
      {
        "key": "checks_challenge_required",
        "title": "Checks challenge required",
        "value": _format_integer(checks_challenge_required),
        "detail": "Check requests that triggered a challenge since startup.",
      },
      {
        "key": "rendered_challenges",
        "title": "Rendered challenges",
        "value": _format_integer(rendered_challenges),
        "detail": "Rendered challenges since startup.",
      },
      {
        "key": "unsolved_challenges",
        "title": "Unsolved challenges",
        "value": _format_integer(unsolved_challenges),
        "detail": "Explicit challenge attempts without success since startup. Abandoned pages are not observable.",
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
      "runtime_warnings": _runtime_warnings(
        samples,
        current_app.config["SETTINGS_BUNDLE"],
      ),
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
      dashboard_script_url=_observability_static_url("dashboard.js"),
      dashboard_style_url=_observability_static_url("dashboard.css"),
      footer_html=DEFAULT_FOOTER_HTML,
      shared_style_url=_observability_static_url("ui.css"),
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


@observability.get("/healthz")
def healthz() -> tuple[str, int]:
  """Return a minimal liveness response for container and proxy health checks."""
  return "ok", HTTPStatus.OK


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


def _observability_static_url(logical_name: str) -> str:
  """Build one observability static asset URL using the optional asset manifest."""
  return url_for(
    "crykeeper_observability.static",
    filename=resolved_asset_name(logical_name),
  )


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

  # First, collect all hosts from check_requests to ensure hosts with only checks appear
  for sample in samples.get("crykeeper_check_requests_total", ()):
    host = sample.labels.get("host", "default")
    # Use "-" as placeholder provider for hosts with only checks
    key = (host, "-")
    grouped.setdefault(
      key,
      {
        "host": host,
        "provider": "-",
        "success": 0.0,
        "total": 0.0,
        "reasons": defaultdict(float),
      },
    )

  # Then, collect verify attempts to populate actual provider and outcome data
  for sample in samples.get("crykeeper_verify_attempts_total", ()):
    labels = sample.labels
    key = (labels.get("host", "default"), labels.get("provider", "-"))
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
    host = row["host"]
    provider = row["provider"]
    reasons = row["reasons"]
    failure_detail = "none"
    if reasons:
      failure_detail = ", ".join(
        f"{reason} {_format_integer(count)}"
        for reason, count in sorted(
          reasons.items(), key=lambda item: (-item[1], item[0])
        )
      )

    check_requests = _sum_labeled_samples(
      samples, "crykeeper_check_requests_total", host=host
    )
    checks_allowed = _sum_labeled_samples(
      samples, "crykeeper_check_requests_total", host=host, outcome="allowed"
    )
    checks_challenge_required = _sum_labeled_samples(
      samples, "crykeeper_check_requests_total", host=host, outcome="challenge_required"
    )
    rendered_challenges = _sum_labeled_samples(
      samples,
      "crykeeper_challenge_requests_total",
      host=host,
      provider=provider,
      outcome="rendered",
    )
    rate_limit_hits = _sum_labeled_samples(
      samples, "crykeeper_rate_limit_hits_total", host=host
    )

    rows.append(
      {
        "host": host,
        "provider": provider,
        "checks_allow_rate": _format_rate(checks_allowed, check_requests),
        "checks_requested_allowed": f"{_format_integer(check_requests)} / {_format_integer(checks_allowed)}",
        "challenges_required_rendered": f"{_format_integer(checks_challenge_required)} / {_format_integer(rendered_challenges)}",
        "success_rate": _format_rate(row["success"], row["total"]),
        "challenges_total_successful": f"{_format_integer(row['total'])} / {_format_integer(row['success'])}",
        "failures": failure_detail,
        "rate_limit_hits": _format_integer(rate_limit_hits),
      }
    )

  # Remove placeholder entries if the same host has a real provider entry
  hosts_with_real_providers = {row["host"] for row in rows if row["provider"] != "-"}
  rows = [
    row
    for row in rows
    if not (row["provider"] == "-" and row["host"] in hosts_with_real_providers)
  ]

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


def _runtime_warnings(
  samples: dict[str, list[object]],
  settings_bundle: object,
) -> list[dict[str, str]]:
  """Build actionable runtime warnings from static config and live metrics."""
  warnings: list[dict[str, str]] = []
  contexts = list(_settings_contexts(settings_bundle))
  default_settings = settings_bundle.default_settings

  if default_settings.trusted_proxy_hops == 0:
    warnings.append(
      _runtime_warning(
        "warn",
        "Trusted proxy hops are disabled",
        "trusted_proxy_hops=0 is fine for direct localhost access, but a TLS-terminating reverse proxy will not make request.is_secure or forwarded client IPs trustworthy.",
      )
    )

  insecure_cookie_contexts = [
    label
    for label, settings in contexts
    if not settings.cookie_secure
    and not (settings.real_captcha_enabled and settings.allow_insecure_local_cap)
  ]
  if insecure_cookie_contexts:
    warnings.append(
      _runtime_warning(
        "warn",
        "Secure cookies are disabled",
        f"{_format_context_labels(insecure_cookie_contexts)} use human_cookie_secure=false. That is suitable for local HTTP wiring only; non-local challenge and verify flows without HTTPS will be rejected.",
      )
    )

  ip_binding_without_proxy_contexts = [
    label
    for label, settings in contexts
    if settings.cookie_binding_mode == "ip-user-agent"
    and default_settings.trusted_proxy_hops == 0
  ]
  if ip_binding_without_proxy_contexts:
    warnings.append(
      _runtime_warning(
        "warn",
        "IP-bound cookies depend on the direct peer",
        f"{_format_context_labels(ip_binding_without_proxy_contexts)} use human_cookie_binding=ip-user-agent while trusted_proxy_hops is disabled. Cookie binding will follow the direct socket peer instead of the forwarded client IP.",
      )
    )

  non_host_cookie_contexts = [
    label
    for label, settings in contexts
    if settings.cookie_secure and not settings.host_cookie_enabled
  ]
  if non_host_cookie_contexts:
    warnings.append(
      _runtime_warning(
        "warn",
        "Secure cookies are not using a __Host- prefix",
        f"{_format_context_labels(non_host_cookie_contexts)} enable secure cookies, but human_cookie_name is not __Host- scoped. Prefer the default secure cookie name when the deployment allows it.",
      )
    )

  insecure_transport_total = _sum_labeled_samples(
    samples,
    "crykeeper_challenge_requests_total",
    outcome="insecure_transport",
  ) + _sum_labeled_samples(
    samples,
    "crykeeper_verify_attempts_total",
    outcome="insecure_transport",
  )
  if insecure_transport_total:
    warnings.append(
      _runtime_warning(
        "fail",
        "Insecure transport rejections observed",
        f"cryKeeper rejected {_format_integer(insecure_transport_total)} challenge or verify requests since startup because the request did not look secure. Check TLS termination, X-Forwarded-Proto forwarding, and trusted_proxy_hops.",
      )
    )

  header_issue_counts = _request_header_issue_counts(samples)
  if header_issue_counts:
    # Filter out user-agent issues if at least one request had a user-agent for that host
    filtered_counts = _filter_user_agent_issues(samples, header_issue_counts)
    if filtered_counts:
      warnings.append(
        _runtime_warning(
          "fail",
          "Missing auth_request headers observed",
          "GET /check saw missing proxy and auth_request headers: "
          + ", ".join(
            f"{header} {_format_integer(count)}"
            for header, count in sorted(filtered_counts.items())
          )
          + " since startup. Check nginx auth_request forwarding for host, user-agent, x-forwarded-for, x-forwarded-proto, x-original-method, and x-original-uri.",
        )
      )

  return sorted(
    warnings,
    key=lambda item: (
      _READINESS_STATUS_ORDER.get(item["status"], len(_READINESS_STATUS_ORDER)),
      item["title"],
    ),
  )


def _settings_contexts(settings_bundle: object):
  """Yield shared defaults followed by every website-specific config context."""
  yield "defaults", settings_bundle.default_settings
  for website in settings_bundle.websites:
    yield f"website[{', '.join(website.domains)}]", website.settings


def _format_context_labels(labels: list[str]) -> str:
  """Render one short human-readable list of config contexts."""
  if len(labels) == 1:
    return labels[0]
  if len(labels) == 2:
    return f"{labels[0]} and {labels[1]}"
  return f"{', '.join(labels[:-1])}, and {labels[-1]}"


def _runtime_warning(status: str, title: str, detail: str) -> dict[str, str]:
  """Build one runtime warning row for the dashboard template."""
  return {
    "status": status,
    "status_label": "Fail" if status == "fail" else "Warn",
    "title": title,
    "detail": detail,
  }


def _request_header_issue_counts(
  samples: dict[str, list[object]],
) -> dict[str, float]:
  """Collapse missing-header observations into one total per header name."""
  counts: dict[str, float] = defaultdict(float)
  for sample in samples.get("crykeeper_request_header_issues_total", ()):
    counts[sample.labels.get("header", "unknown")] += sample.value
  return dict(counts)


def _filter_user_agent_issues(
  samples: dict[str, list[object]],
  header_issue_counts: dict[str, float],
) -> dict[str, float]:
  """Filter out user-agent issues if at least one request had a user-agent for that host."""
  # Get all hosts that have user-agent issues
  user_agent_issue_hosts = set()
  for sample in samples.get("crykeeper_request_header_issues_total", ()):
    if sample.labels.get("header") == "user-agent":
      user_agent_issue_hosts.add(sample.labels.get("host", "default"))

  # For each host with user-agent issues, check if all requests lacked user-agent
  hosts_with_all_missing = set()
  for host in user_agent_issue_hosts:
    user_agent_issues = _sum_labeled_samples(
      samples,
      "crykeeper_request_header_issues_total",
      host=host,
      header="user-agent",
    )
    total_requests = _sum_labeled_samples(
      samples,
      "crykeeper_check_requests_total",
      host=host,
    )
    # Only keep the warning if ALL requests lacked user-agent
    if user_agent_issues == total_requests and total_requests > 0:
      hosts_with_all_missing.add(host)

  # Filter the header_issue_counts: only include user-agent if all requests for that host lacked it
  filtered_counts = {}
  for header, count in header_issue_counts.items():
    if header != "user-agent":
      filtered_counts[header] = count
    else:
      # Calculate total user-agent issues only for hosts where ALL requests lacked user-agent
      total_filtered = 0.0
      for sample in samples.get("crykeeper_request_header_issues_total", ()):
        if (
          sample.labels.get("header") == "user-agent"
          and sample.labels.get("host", "default") in hosts_with_all_missing
        ):
          total_filtered += sample.value
      if total_filtered > 0:
        filtered_counts[header] = total_filtered

  return filtered_counts


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
