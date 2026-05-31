#!/usr/bin/env python3

from __future__ import annotations

import argparse
import http.client
import ssl
import sys
import threading
import time
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

DEFAULT_CONNECT_HOST = "127.0.0.1"
DEFAULT_DUMMY_HOST = "dummy.localhost"
DEFAULT_DUMMY_PATH_PREFIX = "/dummy-check"
DEFAULT_PROTECTED_PATH = "/protected/"
DEFAULT_SKIP_PATH = "/protected/skip-route/"
DEFAULT_BASELINE_PATH = "/"
DEFAULT_BENCHMARK_USER_AGENT = "crykeeper-dev-benchmark/1.0"
FORWARDED_BYPASS_HEADER_NAMES = ("x-crykeeper-token",)


@dataclass(frozen=True)
class Target:
  scheme: str
  connect_host: str
  port: int
  request_host: str
  timeout_seconds: float


@dataclass(frozen=True)
class Scenario:
  name: str
  path: str
  expected_status: int
  headers: dict[str, str]
  note: str


@dataclass(frozen=True)
class ScenarioResult:
  name: str
  expected_status: int
  average_ms: float
  p50_ms: float
  p95_ms: float
  p99_ms: float
  requests_per_second: float
  note: str


def parse_args(argv: list[str]) -> argparse.Namespace:
  parser = argparse.ArgumentParser(
    description=(
      "Compare local nginx response latency with and without cryKeeper auth_request."
    )
  )
  parser.add_argument("--scheme", choices=("http", "https"), default="https")
  parser.add_argument("--connect-host", default=DEFAULT_CONNECT_HOST)
  parser.add_argument("--host", default=DEFAULT_DUMMY_HOST)
  parser.add_argument("--port", type=int, default=8443)
  parser.add_argument("--config", type=Path, default=Path("config.toml"))
  parser.add_argument(
    "--path-prefix",
    default="",
    help=(
      "Explicit cryKeeper path prefix for the target host. If omitted, the script "
      "uses the effective value from --config and otherwise falls back to /dummy-check."
    ),
  )
  parser.add_argument("--baseline-path", default=DEFAULT_BASELINE_PATH)
  parser.add_argument("--protected-path", default=DEFAULT_PROTECTED_PATH)
  parser.add_argument("--skip-path", default=DEFAULT_SKIP_PATH)
  parser.add_argument("--requests", type=int, default=200)
  parser.add_argument("--concurrency", type=int, default=10)
  parser.add_argument("--warmup", type=int, default=20)
  parser.add_argument("--timeout", type=float, default=5.0)
  parser.add_argument("--challenge-status", type=int, default=403)
  parser.add_argument("--user-agent", default=DEFAULT_BENCHMARK_USER_AGENT)
  parser.add_argument(
    "--user-agent-bypass",
    default="",
    help="Optional User-Agent value to benchmark against a configured bypass_user_agents rule.",
  )
  parser.add_argument(
    "--cookie-header",
    default="",
    help=(
      "Optional Cookie header content for the valid-cookie scenario, for example "
      "'__Host-crykeeper_verified=...'. If omitted, the script tries to mint one "
      "through the Dummy verify endpoint."
    ),
  )
  parser.add_argument(
    "--bypass-header",
    default="",
    help=(
      "Optional NAME=VALUE header for the header-bypass scenario. The demo nginx "
      "only mirrors X-CryKeeper-Token into auth_request by default."
    ),
  )
  parser.add_argument(
    "--dry-run",
    action="store_true",
    help="Print the resolved scenarios without sending benchmark traffic.",
  )
  args = parser.parse_args(argv)
  if args.requests < 1:
    parser.error("--requests must be at least 1")
  if args.concurrency < 1:
    parser.error("--concurrency must be at least 1")
  if args.warmup < 0:
    parser.error("--warmup must be 0 or greater")
  if args.timeout <= 0:
    parser.error("--timeout must be greater than 0")
  return args


def main(argv: list[str]) -> int:
  args = parse_args(argv)
  target = Target(
    scheme=args.scheme,
    connect_host=args.connect_host,
    port=args.port,
    request_host=_request_host_header(args.host, args.port),
    timeout_seconds=args.timeout,
  )
  effective_settings = _load_effective_settings(args.config, args.host)
  path_prefix = args.path_prefix or str(
    effective_settings.get("path_prefix") or DEFAULT_DUMMY_PATH_PREFIX
  )

  print(
    (
      f"Target: {target.scheme}://{target.request_host} via "
      f"{target.connect_host}:{target.port}"
    )
  )
  print(f"Path prefix for cookie minting: {path_prefix}")
  if args.config.exists():
    print(f"Config hints: {args.config}")
  else:
    print(f"Config hints: {args.config} not found, using CLI defaults only")
  print(f"Measured requests per scenario: {args.requests}")
  print(f"Warm-up requests per scenario: {args.warmup}")
  print(f"Concurrency: {args.concurrency}")

  if args.dry_run:
    cookie_header = "__Host-crykeeper_verified=dry-run"
  else:
    _ensure_target_reachable(target, args.baseline_path, args.user_agent)
    cookie_header = args.cookie_header.strip() or _mint_dummy_cookie(
      target,
      path_prefix,
      args.user_agent,
    )

  scenarios, skipped = _build_scenarios(
    args,
    effective_settings,
    cookie_header,
  )

  if args.dry_run:
    _print_scenarios(scenarios, skipped)
    return 0

  _print_scenarios(scenarios, skipped)
  results = [
    benchmark_scenario(target, scenario, args.requests, args.concurrency, args.warmup)
    for scenario in scenarios
  ]
  _print_results(results)
  return 0


def _build_scenarios(
  args: argparse.Namespace,
  effective_settings: dict[str, Any],
  cookie_header: str,
) -> tuple[list[Scenario], list[str]]:
  scenarios = [
    Scenario(
      name="baseline_direct",
      path=args.baseline_path,
      expected_status=200,
      headers={"User-Agent": args.user_agent},
      note="Unprotected backend response through nginx without auth_request.",
    ),
    Scenario(
      name="challenge_required",
      path=args.protected_path,
      expected_status=args.challenge_status,
      headers={"User-Agent": args.user_agent},
      note="Protected response without cookie so nginx proxies the challenge page.",
    ),
    Scenario(
      name="valid_cookie",
      path=args.protected_path,
      expected_status=200,
      headers={
        "Cookie": cookie_header,
        "User-Agent": args.user_agent,
      },
      note="Protected response with a real verification cookie.",
    ),
    Scenario(
      name="skip_route",
      path=args.skip_path,
      expected_status=200,
      headers={"User-Agent": args.user_agent},
      note="Protected location that bypasses via skip_routes.",
    ),
  ]
  skipped: list[str] = []

  header_bypass = args.bypass_header.strip() or _first_forwarded_bypass_header(
    effective_settings
  )
  if header_bypass:
    header_name, header_value = _split_header_entry(header_bypass)
    if header_name.lower() not in FORWARDED_BYPASS_HEADER_NAMES:
      skipped.append(
        (
          "header_bypass skipped: the demo nginx only mirrors "
          "X-CryKeeper-Token into auth_request by default"
        )
      )
    else:
      scenarios.append(
        Scenario(
          name="header_bypass",
          path=args.protected_path,
          expected_status=200,
          headers={
            header_name: header_value,
            "User-Agent": args.user_agent,
          },
          note="Protected response bypassed via a forwarded exact-match token header.",
        )
      )
  else:
    skipped.append(
      (
        "header_bypass skipped: no X-CryKeeper-Token token "
        "was found in the effective config and no --bypass-header override was passed"
      )
    )

  if args.user_agent_bypass:
    scenarios.append(
      Scenario(
        name="user_agent_bypass",
        path=args.protected_path,
        expected_status=200,
        headers={"User-Agent": args.user_agent_bypass},
        note="Optional protected response using an explicit bypass_user_agents value.",
      )
    )

  return scenarios, skipped


def benchmark_scenario(
  target: Target,
  scenario: Scenario,
  requests: int,
  concurrency: int,
  warmup: int,
) -> ScenarioResult:
  _warm_up(target, scenario, warmup)

  samples: list[float] = []
  errors: list[str] = []
  lock = threading.Lock()
  started_at = time.perf_counter()
  threads = []

  for worker_requests in _split_requests(requests, concurrency):
    thread = threading.Thread(
      target=_run_worker,
      args=(target, scenario, worker_requests, samples, errors, lock),
      daemon=True,
    )
    threads.append(thread)
    thread.start()

  for thread in threads:
    thread.join()

  elapsed_seconds = time.perf_counter() - started_at
  if errors:
    raise RuntimeError(errors[0])
  if not samples:
    raise RuntimeError(f"No samples were collected for {scenario.name}")

  average_ms = sum(samples) / len(samples)
  return ScenarioResult(
    name=scenario.name,
    expected_status=scenario.expected_status,
    average_ms=average_ms,
    p50_ms=_percentile(samples, 50),
    p95_ms=_percentile(samples, 95),
    p99_ms=_percentile(samples, 99),
    requests_per_second=len(samples) / elapsed_seconds,
    note=scenario.note,
  )


def _ensure_target_reachable(target: Target, path: str, user_agent: str) -> None:
  connection = _open_connection(target)
  try:
    connection.request(
      "GET",
      path,
      headers={
        "Host": target.request_host,
        "User-Agent": user_agent,
      },
    )
    response = connection.getresponse()
    response.read()
  except (http.client.HTTPException, OSError) as exc:
    raise RuntimeError(_connection_error_message(target, path, exc)) from exc
  finally:
    connection.close()


def _warm_up(target: Target, scenario: Scenario, warmup: int) -> None:
  if warmup == 0:
    return

  connection = _open_connection(target)
  try:
    for _ in range(warmup):
      _request_once(connection, target, scenario)
  finally:
    connection.close()


def _run_worker(
  target: Target,
  scenario: Scenario,
  requests: int,
  samples: list[float],
  errors: list[str],
  lock: threading.Lock,
) -> None:
  connection = _open_connection(target)
  try:
    for _ in range(requests):
      if errors:
        return

      started_at = time.perf_counter_ns()
      try:
        _request_once(connection, target, scenario)
      except (http.client.HTTPException, OSError):
        connection.close()
        connection = _open_connection(target)
        _request_once(connection, target, scenario)
      elapsed_ms = (time.perf_counter_ns() - started_at) / 1_000_000

      with lock:
        samples.append(elapsed_ms)
  except Exception as exc:  # pragma: no cover - raised back into main thread
    with lock:
      errors.append(f"{scenario.name} failed: {exc}")
  finally:
    connection.close()


def _request_once(
  connection: http.client.HTTPConnection,
  target: Target,
  scenario: Scenario,
) -> http.client.HTTPResponse:
  connection.request(
    "GET",
    scenario.path,
    headers={"Host": target.request_host, **scenario.headers},
  )
  response = connection.getresponse()
  response.read()
  if response.status != scenario.expected_status:
    raise RuntimeError(
      (
        f"expected HTTP {scenario.expected_status} for {scenario.name} "
        f"at {scenario.path}, got {response.status}"
      )
    )
  return response


def _mint_dummy_cookie(target: Target, path_prefix: str, user_agent: str) -> str:
  connection = _open_connection(target)
  body = urlencode({"return": DEFAULT_PROTECTED_PATH}).encode("utf-8")
  try:
    try:
      connection.request(
        "POST",
        f"{path_prefix}/verify",
        body=body,
        headers={
          "Content-Length": str(len(body)),
          "Content-Type": "application/x-www-form-urlencoded",
          "Host": target.request_host,
          "User-Agent": user_agent,
        },
      )
      response = connection.getresponse()
    except (http.client.HTTPException, OSError) as exc:
      raise RuntimeError(
        _connection_error_message(target, f"{path_prefix}/verify", exc)
      ) from exc

    response.read()
    if response.status != 200:
      raise RuntimeError(
        (
          f"could not mint a verification cookie via {path_prefix}/verify: "
          f"HTTP {response.status}. Use the Dummy demo host or pass --cookie-header."
        )
      )

    set_cookie = _first_header(response.getheaders(), "set-cookie")
    if not set_cookie:
      raise RuntimeError(
        (
          f"{path_prefix}/verify returned HTTP 200 without Set-Cookie. Use the "
          "Dummy demo host or pass --cookie-header explicitly."
        )
      )
    return set_cookie.split(";", 1)[0]
  finally:
    connection.close()


def _open_connection(target: Target) -> http.client.HTTPConnection:
  if target.scheme == "https":
    context = ssl._create_unverified_context()
    return http.client.HTTPSConnection(
      target.connect_host,
      target.port,
      timeout=target.timeout_seconds,
      context=context,
    )

  return http.client.HTTPConnection(
    target.connect_host,
    target.port,
    timeout=target.timeout_seconds,
  )


def _connection_error_message(target: Target, path: str, exc: Exception) -> str:
  return (
    f"could not reach benchmark target {target.scheme}://{target.request_host} "
    f"via {target.connect_host}:{target.port} for {path}: {exc}. "
    "Start the local demo stack with 'docker compose up --build' or point the "
    "script at a running nginx with --scheme, --connect-host, --host, and --port. "
    "Use --dry-run to inspect the resolved scenarios without network traffic."
  )


def _load_effective_settings(config_path: Path, host: str) -> dict[str, Any]:
  if not config_path.exists():
    return {}

  with config_path.open("rb") as handle:
    raw_config = tomllib.load(handle)

  effective = dict(raw_config.get("crykeeper") or {})
  normalized_target_host = _normalize_host(host)
  for website in raw_config.get("website") or []:
    domains = website.get("domains") or []
    if any(_normalize_host(domain) == normalized_target_host for domain in domains):
      effective.update(website)
      break
  return effective


def _normalize_host(value: str) -> str:
  host = value.strip().lower()
  if host.startswith("["):
    return host.split("]", 1)[0].lstrip("[")
  return host.split(":", 1)[0]


def _request_host_header(host: str, port: int) -> str:
  if ":" in host and not host.startswith("["):
    return host
  return f"{host}:{port}"


def _first_forwarded_bypass_header(settings: dict[str, Any]) -> str:
  for entry in settings.get("bypass_headers") or []:
    try:
      header_name, _ = _split_header_entry(entry)
    except ValueError:
      continue
    if header_name.lower() in FORWARDED_BYPASS_HEADER_NAMES:
      return entry
  return ""


def _split_header_entry(value: str) -> tuple[str, str]:
  header_name, separator, header_value = value.partition("=")
  if not separator or not header_name.strip() or not header_value.strip():
    raise ValueError(f"invalid header entry: {value!r}")
  return header_name.strip(), header_value.strip()


def _first_header(headers: list[tuple[str, str]], name: str) -> str:
  lowered_name = name.lower()
  for header_name, header_value in headers:
    if header_name.lower() == lowered_name:
      return header_value
  return ""


def _split_requests(requests: int, concurrency: int) -> list[int]:
  worker_count = min(requests, concurrency)
  floor, remainder = divmod(requests, worker_count)
  return [floor + (1 if index < remainder else 0) for index in range(worker_count)]


def _percentile(samples: list[float], percentile: int) -> float:
  ordered = sorted(samples)
  if len(ordered) == 1:
    return ordered[0]

  rank = (percentile / 100) * (len(ordered) - 1)
  lower_index = int(rank)
  upper_index = min(lower_index + 1, len(ordered) - 1)
  weight = rank - lower_index
  return ordered[lower_index] + (ordered[upper_index] - ordered[lower_index]) * weight


def _print_scenarios(scenarios: list[Scenario], skipped: list[str]) -> None:
  print("Scenarios:")
  for scenario in scenarios:
    print(
      (
        f"  - {scenario.name}: GET {scenario.path} -> HTTP {scenario.expected_status} "
        f"({scenario.note})"
      )
    )
  for reason in skipped:
    print(f"  - {reason}")


def _print_results(results: list[ScenarioResult]) -> None:
  baseline_average_ms = results[0].average_ms
  rows = [
    (
      "scenario",
      "status",
      "req/s",
      "avg ms",
      "p50",
      "p95",
      "p99",
      "delta avg",
    )
  ]
  for result in results:
    rows.append(
      (
        result.name,
        str(result.expected_status),
        f"{result.requests_per_second:.1f}",
        f"{result.average_ms:.2f}",
        f"{result.p50_ms:.2f}",
        f"{result.p95_ms:.2f}",
        f"{result.p99_ms:.2f}",
        f"{result.average_ms - baseline_average_ms:+.2f}",
      )
    )

  widths = [max(len(row[index]) for row in rows) for index in range(len(rows[0]))]
  print("\nResults:")
  for index, row in enumerate(rows):
    formatted = "  ".join(
      value.ljust(widths[column_index]) for column_index, value in enumerate(row)
    )
    print(formatted)
    if index == 0:
      print("  ".join("-" * width for width in widths))


if __name__ == "__main__":
  try:
    raise SystemExit(main(sys.argv[1:]))
  except RuntimeError as exc:
    print(f"error: {exc}", file=sys.stderr)
    raise SystemExit(1)
  except KeyboardInterrupt:
    raise SystemExit(130)
