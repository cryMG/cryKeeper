import hmac
import re
import time
from http import HTTPStatus
from ipaddress import ip_address, ip_network
from urllib.parse import urlencode, urlsplit

from flask import (
  Blueprint,
  Response,
  current_app,
  jsonify,
  make_response,
  redirect,
  render_template,
  request,
)

from .captcha.altcha import create_challenge as create_altcha_challenge
from .captcha.altcha import verify_request as verify_altcha_request
from .captcha.cap import CapVerificationResult
from .captcha.cap import verify_token as verify_cap_token
from .captcha.dummy import verify_request as verify_dummy_request
from .captcha.hcaptcha import verify_request as verify_hcaptcha_request
from .config import (
  DEFAULT_FOOTER_HTML,
  ENFORCEMENT_MODE_CHALLENGE_PASSTHROUGH,
  ENFORCEMENT_MODE_LOG_ONLY,
  normalize_host_name,
)
from .cookies import (
  TOKEN_SUBJECT_CHALLENGE_PASSTHROUGH,
  TOKEN_SUBJECT_HUMAN,
  issue_token_for_client,
  verify_token_for_client,
)
from .i18n import get_translations
from .ratelimit import RateLimitRule
from .security import normalize_return_path

crykeeper = Blueprint(
  "crykeeper", __name__, static_folder="static", static_url_path="/static"
)

KNOWN_SEARCH_ENGINE_USER_AGENTS = (
  (
    "google",
    re.compile(
      r"\b(?:Googlebot|GoogleOther|Google-InspectionTool|AdsBot-Google|Mediapartners-Google|APIs-Google|Storebot-Google)\b",
      re.IGNORECASE,
    ),
  ),
  ("bing", re.compile(r"\b(?:bingbot|BingPreview|AdIdxBot)\b", re.IGNORECASE)),
  ("duckduckgo", re.compile(r"\bDuckDuckBot\b", re.IGNORECASE)),
  ("yahoo", re.compile(r"\bSlurp\b", re.IGNORECASE)),
  (
    "yandex",
    re.compile(
      r"\bYandex(?:Bot|Images|Video|MobileBot|AccessibilityBot)\b",
      re.IGNORECASE,
    ),
  ),
  ("baidu", re.compile(r"\bBaiduspider\b", re.IGNORECASE)),
  ("apple", re.compile(r"\bApplebot\b", re.IGNORECASE)),
  ("petal", re.compile(r"\bPetalBot\b", re.IGNORECASE)),
  ("seznam", re.compile(r"\bSeznamBot\b", re.IGNORECASE)),
)


@crykeeper.get("/check")
def check() -> tuple[str, int] | Response:
  """Validate the signed cookie for nginx auth_request subrequests."""
  settings = _settings()
  request_host = _request_host_name()
  _record_check_header_issues(request_host)
  original_uri = _original_request_uri()
  bypass_reason = _auth_bypass_reason(settings)
  if bypass_reason is not None:
    _observability().record_auth_bypass(
      request_host, _bypass_metric_reason(bypass_reason)
    )
    _observability().record_check(request_host, "bypass")
    current_app.logger.info(
      "Bypassing auth",
      extra={
        "reason": bypass_reason,
        "request_method": _original_request_method(),
        "request_path": _original_request_path(),
        "client_ip": _client_ip_log_value(),
      },
    )
    return "", HTTPStatus.NO_CONTENT

  token = request.cookies.get(settings.cookie_name)
  payload = verify_token_for_client(
    settings.secret_key,
    token,
    client_binding=_client_binding_value(settings.cookie_binding_mode),
    allowed_subjects=_check_allowed_token_subjects(settings),
  )
  return_path = normalize_return_path(
    original_uri,
    settings.blocked_return_prefixes,
    settings.max_return_path_length,
  )

  if payload is not None:
    if payload["sub"] == TOKEN_SUBJECT_CHALLENGE_PASSTHROUGH:
      _observability().record_check(request_host, "challenge_passthrough_allowed")
      current_app.logger.info(
        "Challenge passthrough cookie allowed request",
        extra={
          "return_path": return_path,
          "request_method": _original_request_method(),
          "request_path": _original_request_path(),
          "client_ip": _client_ip_log_value(),
        },
      )
      return "", HTTPStatus.NO_CONTENT

    _observability().record_check(request_host, "allowed")
    return "", HTTPStatus.NO_CONTENT

  if settings.enforcement_mode == ENFORCEMENT_MODE_LOG_ONLY:
    _observability().record_check(request_host, "log_only_challenge_required")
    current_app.logger.info(
      "Log-only mode would redirect to challenge",
      extra={
        "return_path": return_path,
        "request_method": _original_request_method(),
        "request_path": _original_request_path(),
        "client_ip": _client_ip_log_value(),
      },
    )
    return "", HTTPStatus.NO_CONTENT

  # nginx reads this header and converts the 401 into a redirect to /crykeeper/challenge.
  response = make_response("", HTTPStatus.UNAUTHORIZED)
  response.headers["X-Auth-Redirect"] = _crykeeper_url(
    settings, "/challenge", return_path=return_path
  )
  _observability().record_check(request_host, "challenge_required")
  current_app.logger.info(
    "Access denied, redirecting to challenge", extra={"return_path": return_path}
  )
  return response


@crykeeper.get("/challenge")
def challenge() -> Response:
  """Render the interstitial page that triggers the active verification provider."""
  settings = _settings()
  request_host = _request_host_name()
  return_path = normalize_return_path(
    request.args.get("return"),
    settings.blocked_return_prefixes,
    settings.max_return_path_length,
  )

  secure_transport_response = _enforce_secure_transport(return_path)
  if secure_transport_response is not None:
    _observability().record_challenge(
      request_host, settings.verification_mode, "insecure_transport"
    )
    _observability().record_unsolved_challenge(
      request_host,
      settings.verification_mode,
      "insecure_transport",
    )
    return secure_transport_response

  rate_limit_response = _rate_limit_response("challenge", return_path)
  if rate_limit_response is not None:
    return rate_limit_response

  _observability().record_challenge(
    request_host, settings.verification_mode, "rendered"
  )
  return _render_challenge(return_path)


@crykeeper.post("/verify")
def verify() -> Response:
  """Complete the active provider verification and issue the signed human cookie."""
  settings = _settings()
  request_host = _request_host_name()
  verify_started_at = time.perf_counter()
  return_path = normalize_return_path(
    request.form.get("return"),
    settings.blocked_return_prefixes,
    settings.max_return_path_length,
  )

  secure_transport_response = _enforce_secure_transport(return_path)
  if secure_transport_response is not None:
    _observability().record_verify_result(
      request_host,
      settings.verification_mode,
      "insecure_transport",
      "insecure_transport",
    )
    _observability().record_unsolved_challenge(
      request_host,
      settings.verification_mode,
      "insecure_transport",
    )
    _observability().record_verify_duration(
      request_host,
      settings.verification_mode,
      "insecure_transport",
      time.perf_counter() - verify_started_at,
    )
    return secure_transport_response

  rate_limit_response = _rate_limit_response("verify", return_path)
  if rate_limit_response is not None:
    _observability().record_verify_duration(
      request_host,
      settings.verification_mode,
      "rate_limited",
      time.perf_counter() - verify_started_at,
    )
    return rate_limit_response

  provider_started_at = time.perf_counter()
  verification_result = _verification_result(settings)
  verification_outcome = _verification_metric_outcome(verification_result)
  _observability().record_provider_result(
    request_host,
    settings.verification_mode,
    "verify",
    verification_outcome,
    time.perf_counter() - provider_started_at,
  )
  if not verification_result.success:
    error_key = verification_result.error_key or (
      "error_unavailable" if verification_result.retryable else "error_failed"
    )
    status_code = verification_result.status_code
    if status_code == HTTPStatus.OK:
      status_code = (
        HTTPStatus.BAD_GATEWAY
        if verification_result.retryable
        else HTTPStatus.FORBIDDEN
      )

    current_app.logger.warning(
      "%s verification failed",
      settings.verification_mode.upper(),
      extra={
        "retryable": verification_result.retryable,
        "verification_payload": verification_result.payload or {},
      },
    )
    _observability().record_verify_result(
      request_host,
      settings.verification_mode,
      verification_outcome,
      _verification_metric_reason(verification_result),
    )
    _observability().record_unsolved_challenge(
      request_host,
      settings.verification_mode,
      _verification_metric_reason(verification_result),
    )
    _observability().record_verify_duration(
      request_host,
      settings.verification_mode,
      verification_outcome,
      time.perf_counter() - verify_started_at,
    )
    if settings.enforcement_mode == ENFORCEMENT_MODE_CHALLENGE_PASSTHROUGH:
      current_app.logger.info(
        "Challenge passthrough granted after failed verification",
        extra={
          "return_path": return_path,
          "reason": _verification_metric_reason(verification_result),
        },
      )
      return _render_return_page_with_access_cookie(
        return_path,
        settings,
        TOKEN_SUBJECT_CHALLENGE_PASSTHROUGH,
      )

    return _render_challenge(
      return_path,
      error_key=error_key,
      status_code=status_code,
    )

  response = _render_return_page_with_access_cookie(
    return_path,
    settings,
    TOKEN_SUBJECT_HUMAN,
  )
  _observability().record_verify_result(
    request_host,
    settings.verification_mode,
    "success",
    "none",
  )
  _observability().record_verify_duration(
    request_host,
    settings.verification_mode,
    "success",
    time.perf_counter() - verify_started_at,
  )
  log_message = {
    "cap": "Cap verification completed",
    "hcaptcha": "hCaptcha verification completed",
    "altcha": "ALTCHA verification completed",
  }.get(settings.verification_mode, "Dummy verification completed")
  current_app.logger.info(log_message, extra={"return_path": return_path})
  return response


@crykeeper.get("/altcha/challenge")
def altcha_challenge() -> Response:
  """Return one fresh ALTCHA challenge when ALTCHA mode is active for the host."""
  settings = _settings()
  request_host = _request_host_name()
  if not settings.altcha_enabled:
    response = jsonify({"error": "ALTCHA mode is not active for this host."})
    response.status_code = HTTPStatus.NOT_FOUND
    response.headers["Cache-Control"] = "no-store"
    return response

  return_path = normalize_return_path(
    request.args.get("return"),
    settings.blocked_return_prefixes,
    settings.max_return_path_length,
  )

  secure_transport_response = _enforce_secure_transport(return_path)
  if secure_transport_response is not None:
    return _json_error_response(
      {"error": "Verification is only available over HTTPS on non-local hosts."},
      HTTPStatus.BAD_REQUEST,
    )

  decision = _rate_limit_decision("challenge")
  if decision is not None:
    return _json_error_response(
      {"error": "Too many verification attempts. Please wait and try again."},
      HTTPStatus.TOO_MANY_REQUESTS,
      retry_after_seconds=decision.retry_after_seconds,
    )

  challenge_started_at = time.perf_counter()
  challenge_payload = create_altcha_challenge(settings)
  _observability().record_provider_result(
    request_host,
    "altcha",
    "challenge",
    "success",
    time.perf_counter() - challenge_started_at,
  )
  response = jsonify(challenge_payload)
  response.status_code = HTTPStatus.OK
  response.headers["Cache-Control"] = "no-store"
  return response


@crykeeper.get("/clear")
def clear() -> Response:
  """Clear the signed human-verification cookie and redirect to a safe local path."""
  settings = _settings()
  return_path = normalize_return_path(
    request.args.get("return"),
    settings.blocked_return_prefixes,
    settings.max_return_path_length,
  )

  response = redirect("/" + return_path.lstrip("/"), code=HTTPStatus.FOUND)
  _clear_verification_cookie(response, settings)
  response.headers["Cache-Control"] = "no-store"
  current_app.logger.info(
    "Cleared verification cookie", extra={"return_path": return_path}
  )
  return response


@crykeeper.get("/healthz")
def healthz() -> tuple[str, int]:
  """Return a minimal liveness response for container and proxy health checks."""
  return "ok", HTTPStatus.OK


def _render_challenge(
  return_path: str,
  error_key: str | None = None,
  status_code: int = HTTPStatus.OK,
  rate_limited: bool = False,
  retry_after_seconds: int | None = None,
) -> Response:
  """Render the challenge template with no-store and clickjacking protection headers."""
  settings = _settings()
  language_code, translations = get_translations(request.accept_languages)
  challenge_context = _challenge_template_context(settings)
  client_translation_keys = challenge_context["client_translation_keys"]
  client_translations = {key: translations[key] for key in client_translation_keys}
  response = make_response(
    render_template(
      "challenge.html",
      language_code=language_code,
      translations=translations,
      client_translations=client_translations,
      footer_html=_challenge_footer_html(settings, language_code),
      return_path=return_path,
      error_message=translations.get(error_key) if error_key else None,
      auto_start=not error_key and not rate_limited,
      rate_limited=rate_limited,
      verification_mode=settings.verification_mode,
      verify_action_url=_crykeeper_path(settings, "/verify"),
      challenge_shared_style_url=_crykeeper_path(settings, "/static/ui.css"),
      challenge_shared_script_url=_crykeeper_path(
        settings, "/static/challenge-common.js"
      ),
      challenge_runtime_script_url=challenge_context["runtime_script_url"],
      provider_external_scripts=challenge_context["external_scripts"],
      provider_options=challenge_context["provider_options"],
      provider_template=challenge_context["provider_template"],
      initial_status_text=translations[challenge_context["initial_status_key"]],
    ),
    status_code,
  )
  # Challenge responses should never be cached because they carry per-request return targets.
  response.headers["Cache-Control"] = "no-store"
  response.headers["Pragma"] = "no-cache"
  response.headers["Referrer-Policy"] = "same-origin"
  response.headers["X-Content-Type-Options"] = "nosniff"
  response.headers["X-Frame-Options"] = "DENY"
  response.headers["Content-Security-Policy"] = _content_security_policy(settings)
  if retry_after_seconds is not None:
    response.headers["Retry-After"] = str(retry_after_seconds)
  return response


def _render_return_page(return_path: str, settings: object) -> Response:
  """Render the post-verify continuation page that sends the browser to the target."""
  language_code, translations = get_translations(request.accept_languages)
  response = make_response(
    render_template(
      "verify_redirect.html",
      language_code=language_code,
      translations=translations,
      footer_html=_challenge_footer_html(settings, language_code),
      return_path=return_path,
      challenge_shared_style_url=_crykeeper_path(settings, "/static/ui.css"),
      challenge_shared_script_url=_crykeeper_path(
        settings, "/static/challenge-common.js"
      ),
      verify_redirect_script_url=_crykeeper_path(
        settings, "/static/verify-redirect.js"
      ),
    ),
    HTTPStatus.OK,
  )
  response.headers["Cache-Control"] = "no-store"
  response.headers["Pragma"] = "no-cache"
  response.headers["Referrer-Policy"] = "same-origin"
  response.headers["X-Content-Type-Options"] = "nosniff"
  response.headers["X-Frame-Options"] = "DENY"
  response.headers["Content-Security-Policy"] = _return_page_content_security_policy()
  return response


def _challenge_footer_html(settings: object, language_code: str) -> str:
  """Return the configured footer or the shared default when none is set."""
  configured_footer = settings.footer_html.resolve(language_code).strip()
  if configured_footer:
    return configured_footer
  return DEFAULT_FOOTER_HTML


def _set_verification_cookie(response: Response, settings: object, token: str) -> None:
  """Write the signed verification cookie using the shared browser attributes."""
  # The cookie is the only verification state; no server-side session is stored.
  response.set_cookie(
    settings.cookie_name,
    token,
    max_age=settings.cookie_ttl_seconds,
    httponly=True,
    secure=settings.cookie_secure,
    samesite="Lax",
    path="/",
  )


def _clear_verification_cookie(response: Response, settings: object) -> None:
  """Expire the verification cookie with the same browser attributes used at issue time."""
  response.delete_cookie(
    settings.cookie_name,
    httponly=True,
    secure=settings.cookie_secure,
    samesite="Lax",
    path="/",
  )


def _render_return_page_with_access_cookie(
  return_path: str,
  settings: object,
  subject: str,
) -> Response:
  """Issue one signed access cookie and return the browser continuation page."""
  token = issue_token_for_client(
    settings.secret_key,
    settings.cookie_ttl_seconds,
    client_binding=_client_binding_value(settings.cookie_binding_mode),
    subject=subject,
  )
  response = _render_return_page(return_path, settings)
  _set_verification_cookie(response, settings, token)
  return response


def _check_allowed_token_subjects(settings: object) -> tuple[str, ...]:
  """Return which signed cookie subjects should count as pass-through in /check."""
  if settings.enforcement_mode == ENFORCEMENT_MODE_CHALLENGE_PASSTHROUGH:
    return (TOKEN_SUBJECT_HUMAN, TOKEN_SUBJECT_CHALLENGE_PASSTHROUGH)
  return (TOKEN_SUBJECT_HUMAN,)


def _rate_limit_response(scope: str, return_path: str) -> Response | None:
  """Best-effort in-process abuse throttling for challenge and verify endpoints."""
  decision = _rate_limit_decision(scope)
  if decision is None:
    return None

  settings = _settings()
  request_host = _request_host_name()
  if scope == "challenge":
    _observability().record_challenge(
      request_host,
      settings.verification_mode,
      "rate_limited",
    )
    _observability().record_unsolved_challenge(
      request_host,
      settings.verification_mode,
      "rate_limited",
    )
  else:
    _observability().record_verify_result(
      request_host,
      settings.verification_mode,
      "rate_limited",
      "rate_limited",
    )
    _observability().record_unsolved_challenge(
      request_host,
      settings.verification_mode,
      "rate_limited",
    )

  return _render_challenge(
    return_path,
    error_key="error_rate_limited",
    status_code=HTTPStatus.TOO_MANY_REQUESTS,
    rate_limited=True,
    retry_after_seconds=decision.retry_after_seconds,
  )


def _rate_limit_decision(scope: str) -> object | None:
  """Return the limiter decision for one public endpoint when a client is blocked."""
  settings = _settings()
  rate_limiter = current_app.extensions["crykeeper_rate_limiter"]
  decision = rate_limiter.check(
    f"{scope}:{_request_host_name() or 'default'}:{_rate_limit_client_key()}",
    _rate_limit_rule(scope, settings),
  )
  if decision.allowed:
    return None

  _observability().record_rate_limit_hit(
    _request_host_name(),
    scope,
    rate_limiter.metrics_backend_name,
  )

  current_app.logger.warning(
    "Rate limit exceeded",
    extra={
      "scope": scope,
      "client_ip": _client_ip_log_value(),
      "retry_after_seconds": decision.retry_after_seconds,
    },
  )
  return decision


def _rate_limit_rule(scope: str, settings: object) -> RateLimitRule:
  """Return the configured rate-limit policy for the requested public endpoint."""
  if scope == "challenge":
    return RateLimitRule(
      max_requests=settings.challenge_rate_limit_requests,
      window_seconds=settings.challenge_rate_limit_window_seconds,
      block_seconds=settings.challenge_rate_limit_block_seconds,
    )

  return RateLimitRule(
    max_requests=settings.verify_rate_limit_requests,
    window_seconds=settings.verify_rate_limit_window_seconds,
    block_seconds=settings.verify_rate_limit_block_seconds,
  )


def _rate_limit_client_key() -> str:
  """Group abusive traffic by sanitized client IP, then fall back to User-Agent."""
  client_ip = _client_ip_value()
  if client_ip:
    return client_ip
  return f"ua={_normalized_user_agent(request.headers.get('User-Agent')) or 'unknown'}"


def _enforce_secure_transport(return_path: str) -> Response | None:
  """Reject non-local verification flows that are not protected by HTTPS cookies."""
  settings = _settings()

  if settings.cookie_secure and request.is_secure:
    return None

  if settings.cookie_secure:
    current_app.logger.warning(
      "Rejected verification flow over insecure transport",
      extra={"request_host": request.host, "return_path": return_path},
    )
    return _render_challenge(
      return_path,
      error_key="error_insecure_transport",
      status_code=HTTPStatus.BAD_REQUEST,
    )

  if _is_local_request_host():
    return None

  current_app.logger.warning(
    "Rejected non-local verification flow without secure cookies",
    extra={"request_host": request.host, "return_path": return_path},
  )
  return _render_challenge(
    return_path,
    error_key="error_insecure_transport",
    status_code=HTTPStatus.BAD_REQUEST,
  )


def _content_security_policy(settings: object) -> str:
  """Allow only the local challenge script plus the configured Cap origins."""
  script_sources = ["'self'"]
  script_element_sources = ["'self'"]
  style_sources = ["'self'", "'unsafe-inline'"]
  connect_sources = ["'self'"]
  worker_sources = ["'self'"]
  frame_sources: list[str] = []

  if settings.cap_enabled:
    script_sources.extend(["'unsafe-eval'", "'wasm-unsafe-eval'"])
    script_sources = _sources_with_origin(script_sources, settings.cap_asset_base_url)
    script_element_sources = _sources_with_origin(
      script_element_sources,
      settings.cap_asset_base_url,
    )
    script_element_sources.append("'unsafe-inline'")
    connect_sources = _sources_with_origin(
      connect_sources,
      settings.cap_public_base_url,
      settings.cap_asset_base_url,
    )
    worker_sources.append("blob:")

  if settings.hcaptcha_enabled:
    hcaptcha_sources = ("https://hcaptcha.com", "https://*.hcaptcha.com")
    script_sources.extend(hcaptcha_sources)
    script_element_sources.extend(hcaptcha_sources)
    style_sources.extend(hcaptcha_sources)
    connect_sources.extend(hcaptcha_sources)
    frame_sources.extend(hcaptcha_sources)

  if settings.altcha_enabled:
    script_sources = _sources_with_origin(script_sources, settings.altcha_script_url)
    script_element_sources = _sources_with_origin(
      script_element_sources,
      settings.altcha_effective_script_url,
    )
    worker_sources.append("blob:")

  directives = (
    ("default-src", ["'self'"]),
    ("base-uri", ["'none'"]),
    ("frame-ancestors", ["'none'"]),
    ("frame-src", _dedupe(frame_sources or ["'self'"])),
    ("form-action", ["'self'"]),
    ("object-src", ["'none'"]),
    ("script-src", _dedupe(script_sources)),
    ("script-src-elem", _dedupe(script_element_sources)),
    ("script-src-attr", ["'none'"]),
    ("style-src", _dedupe(style_sources)),
    ("img-src", ["'self'", "data:"]),
    ("font-src", ["'self'", "data:"]),
    ("connect-src", _dedupe(connect_sources)),
    ("worker-src", _dedupe(worker_sources)),
  )
  return "; ".join(f"{name} {' '.join(values)}" for name, values in directives)


def _return_page_content_security_policy() -> str:
  """Allow only the local assets needed for the post-verify continuation page."""
  directives = (
    ("default-src", ["'self'"]),
    ("base-uri", ["'none'"]),
    ("frame-ancestors", ["'none'"]),
    ("frame-src", ["'none'"]),
    ("form-action", ["'none'"]),
    ("object-src", ["'none'"]),
    ("script-src", ["'self'"]),
    ("script-src-elem", ["'self'"]),
    ("script-src-attr", ["'none'"]),
    ("style-src", ["'self'"]),
    ("img-src", ["'self'", "data:"]),
    ("font-src", ["'self'", "data:"]),
    ("connect-src", ["'none'"]),
    ("worker-src", ["'none'"]),
  )
  return "; ".join(f"{name} {' '.join(values)}" for name, values in directives)


def _sources_with_origin(sources: list[str], *urls: str) -> list[str]:
  """Append origins derived from configured absolute URLs."""
  result = list(sources)
  for url in urls:
    origin = _origin_from_url(url)
    if origin is not None:
      result.append(origin)
  return result


def _origin_from_url(url: str) -> str | None:
  """Extract a CSP-safe origin from an absolute URL."""
  parsed = urlsplit(url)
  if not parsed.scheme or not parsed.netloc:
    return None
  return f"{parsed.scheme}://{parsed.netloc}"


def _dedupe(values: list[str]) -> list[str]:
  """Keep CSP directives stable while removing duplicate origins."""
  return list(dict.fromkeys(values))


def _client_binding_value(binding_mode: str) -> str | None:
  """Bind cookies to stable client properties to raise the replay bar without sessions."""
  if binding_mode == "none":
    return None

  parts = [f"ua={_normalized_user_agent(request.headers.get('User-Agent'))}"]
  if binding_mode == "ip-user-agent":
    parts.append(f"ip={_client_ip_value()}")
  return "|".join(parts)


def _normalized_user_agent(value: str | None) -> str:
  """Collapse insignificant whitespace so proxy formatting differences do not break tokens."""
  return " ".join((value or "").split()).lower()


def _client_ip_value() -> str:
  """Use the post-proxy remote peer instead of parsing untrusted forwarded chains here."""
  return _normalized_ip(request.remote_addr) or ""


def _client_ip_log_value() -> str:
  """Return the client IP as it should appear in log records for this request."""
  client_ip = _client_ip_value()
  if not client_ip:
    return ""

  if not _settings().anonymize_client_ip_logs:
    return client_ip

  return _anonymized_log_ip(client_ip)


def _anonymized_log_ip(value: str) -> str:
  """Reduce IP precision in logs while keeping coarse subnet context."""
  try:
    parsed_ip = ip_address(value)
  except ValueError:
    return value

  prefix_length = 24 if parsed_ip.version == 4 else 48
  return ip_network(f"{parsed_ip.compressed}/{prefix_length}", strict=False).compressed


def _is_local_request_host() -> bool:
  """Allow local HTTP wiring tests while enforcing HTTPS on non-loopback hosts."""
  host = _request_host_name()
  if not host:
    return False
  if host == "localhost":
    return True

  try:
    return ip_address(host).is_loopback
  except ValueError:
    return False


def _request_host_name() -> str:
  """Return the normalized host name without a port suffix."""
  return normalize_host_name(request.host)


def _original_request_method() -> str:
  """Return the original client request method forwarded by the reverse proxy."""
  return request.headers.get("X-Original-Method", request.method).strip().upper()


def _original_request_uri() -> str:
  """Return the original client request URI forwarded by the reverse proxy."""
  return request.headers.get("X-Original-URI", "/")


def _original_request_path() -> str:
  """Extract the path component from the original client request URI."""
  parsed_uri = urlsplit(_original_request_uri())
  return parsed_uri.path or "/"


def _record_check_header_issues(request_host: str) -> None:
  """Track missing auth_request forwarding headers without changing fallbacks."""
  if not (request.headers.get("Host") or "").strip():
    _observability().record_request_header_issue(
      request_host,
      "check",
      "host",
    )

  if not (request.headers.get("User-Agent") or "").strip():
    _observability().record_request_header_issue(
      request_host,
      "check",
      "user-agent",
    )

  if not (request.headers.get("X-Forwarded-For") or "").strip():
    _observability().record_request_header_issue(
      request_host,
      "check",
      "x-forwarded-for",
    )

  if not (request.headers.get("X-Forwarded-Proto") or "").strip():
    _observability().record_request_header_issue(
      request_host,
      "check",
      "x-forwarded-proto",
    )

  if not (request.headers.get("X-Original-Method") or "").strip():
    _observability().record_request_header_issue(
      request_host,
      "check",
      "x-original-method",
    )

  if not (request.headers.get("X-Original-URI") or "").strip():
    _observability().record_request_header_issue(
      request_host,
      "check",
      "x-original-uri",
    )


def _skip_auth_route_matches(settings: object) -> bool:
  """Return true when the current auth_request subrequest should be bypassed."""
  original_method = _original_request_method()
  original_path = _original_request_path()
  return any(
    rule.matches(original_path, original_method) for rule in settings.skip_routes
  )


def _request_user_agent() -> str:
  """Return the raw user agent header for bypass checks and cookie binding."""
  return request.headers.get("User-Agent", "")


def _bypass_ip_reason(settings: object) -> str | None:
  """Return the matched bypass IP rule, if the client address is allowlisted."""
  normalized_client_ip = _client_ip_value()
  if not normalized_client_ip:
    return None

  try:
    client_ip = ip_address(normalized_client_ip)
  except ValueError:
    return None

  for rule in settings.bypass_ips:
    if client_ip in rule.network:
      return f"bypass_ip:{rule.value}"

  return None


def _bypass_header_reason(settings: object) -> str | None:
  """Return the matched header bypass rule, if one applies."""
  for rule in settings.bypass_headers:
    header_value = request.headers.get(rule.header_name)
    if header_value is None:
      continue

    if hmac.compare_digest(header_value, rule.value):
      return f"bypass_header:{rule.header_name}"

  return None


def _bypass_user_agent_reason(settings: object) -> str | None:
  """Return the matched user-agent bypass rule, if one applies."""
  user_agent = _request_user_agent()
  if not user_agent:
    return None

  for rule in settings.bypass_user_agents:
    if rule.matches(user_agent):
      return f"bypass_user_agent:{rule.pattern}"

  return None


def _known_search_engine_reason(settings: object) -> str | None:
  """Return the matched search engine name when crawler bypass is enabled."""
  if not settings.allow_known_search_engines:
    return None

  user_agent = _request_user_agent()
  if not user_agent:
    return None

  for engine_name, pattern in KNOWN_SEARCH_ENGINE_USER_AGENTS:
    if pattern.search(user_agent) is not None:
      return f"known_search_engine:{engine_name}"

  return None


def _auth_bypass_reason(settings: object) -> str | None:
  """Return the first configured auth bypass reason for the current request."""
  if _skip_auth_route_matches(settings):
    return "skip_route"

  header_reason = _bypass_header_reason(settings)
  if header_reason is not None:
    return header_reason

  ip_reason = _bypass_ip_reason(settings)
  if ip_reason is not None:
    return ip_reason

  user_agent_reason = _bypass_user_agent_reason(settings)
  if user_agent_reason is not None:
    return user_agent_reason

  return _known_search_engine_reason(settings)


def _normalized_ip(value: str | None) -> str | None:
  """Canonicalize IP strings so equivalent textual forms hash to the same binding."""
  if value is None:
    return None

  candidate = value.strip()
  if not candidate:
    return None

  try:
    return ip_address(candidate).compressed
  except ValueError:
    return candidate


def _settings() -> object:
  """Resolve the effective settings for the current request host."""
  return current_app.config["SETTINGS_BUNDLE"].settings_for_host(request.host)


def _observability() -> object:
  """Resolve the shared metrics collector stored on the Flask app."""
  return current_app.extensions["crykeeper_observability"]


def _challenge_template_context(settings: object) -> dict[str, object]:
  """Return provider-specific template and script settings for the challenge page."""
  if settings.cap_enabled:
    return {
      "client_translation_keys": (
        "progress_checking",
        "progress_verifying",
        "retry_button",
        "reload_button",
        "error_failed",
        "error_widget_load",
        "error_widget_runtime",
        "status_retry_ready",
        "status_reload_ready",
      ),
      "runtime_script_url": _crykeeper_path(settings, "/static/challenge-cap.js"),
      "external_scripts": (
        {
          "src": settings.cap_widget_script_url,
          "module": False,
          "async_attr": False,
          "defer_attr": True,
        },
      ),
      "provider_options": {
        "apiEndpoint": settings.cap_api_endpoint,
        "wasmUrl": settings.cap_wasm_script_url,
      },
      "provider_template": "providers/cap.html",
      "initial_status_key": "progress_idle",
    }

  if settings.hcaptcha_enabled:
    return {
      "client_translation_keys": (
        "progress_checking",
        "progress_verifying",
        "error_widget_load",
        "error_widget_runtime",
        "status_hcaptcha_ready",
        "status_retry_ready",
        "status_reload_ready",
      ),
      "runtime_script_url": _crykeeper_path(settings, "/static/challenge-hcaptcha.js"),
      "external_scripts": (
        {
          "src": settings.hcaptcha_script_url,
          "module": False,
          "async_attr": False,
          "defer_attr": True,
        },
      ),
      "provider_options": {"siteKey": settings.hcaptcha_site_key},
      "provider_template": "providers/hcaptcha.html",
      "initial_status_key": "status_hcaptcha_ready",
    }

  if settings.altcha_enabled:
    altcha_script_url = settings.altcha_effective_script_url
    return {
      "client_translation_keys": (
        "progress_checking",
        "progress_verifying",
        "progress_complete",
        "error_widget_load",
        "error_widget_runtime",
        "status_altcha_ready",
        "status_retry_ready",
      ),
      "runtime_script_url": _crykeeper_path(settings, "/static/challenge-altcha.js"),
      "external_scripts": (
        {
          "src": altcha_script_url,
          "module": True,
          "async_attr": False,
          "defer_attr": False,
        },
      ),
      "provider_options": {
        "challengeUrl": _crykeeper_path(settings, "/altcha/challenge"),
      },
      "provider_template": "providers/altcha.html",
      "initial_status_key": "status_altcha_ready",
    }

  return {
    "client_translation_keys": (
      "dummy_progress_running",
      "progress_complete",
    ),
    "runtime_script_url": _crykeeper_path(settings, "/static/challenge-dummy.js"),
    "external_scripts": (),
    "provider_options": {},
    "provider_template": "providers/dummy.html",
    "initial_status_key": "status_dummy_ready",
  }


def _verification_result(settings: object) -> object:
  """Run the active verification provider for the current challenge submission."""
  if settings.cap_enabled:
    cap_response_token = request.form.get("cap-token", "").strip()
    if not cap_response_token:
      current_app.logger.warning("Missing Cap token during verification")
      return CapVerificationResult(
        success=False,
        retryable=False,
        error_key="error_incomplete",
        status_code=HTTPStatus.BAD_REQUEST,
        message="Missing Cap token during verification.",
        payload=None,
      )

    return verify_cap_token(
      settings.cap_siteverify_url,
      settings.cap_secret_key,
      cap_response_token,
      settings.cap_verify_timeout_seconds,
    )

  if settings.hcaptcha_enabled:
    return verify_hcaptcha_request(settings, request, _client_ip_value())

  if settings.altcha_enabled:
    return verify_altcha_request(settings, request, _client_ip_value())

  return verify_dummy_request(settings, request, _client_ip_value())


def _json_error_response(
  payload: dict[str, str],
  status_code: int,
  retry_after_seconds: int | None = None,
) -> Response:
  """Return one small JSON error response for provider-specific API endpoints."""
  response = jsonify(payload)
  response.status_code = status_code
  response.headers["Cache-Control"] = "no-store"
  if retry_after_seconds is not None:
    response.headers["Retry-After"] = str(retry_after_seconds)
  return response


def _crykeeper_path(settings: object, suffix: str) -> str:
  """Build a crykeeper-local URL path from the effective per-website prefix."""
  return f"{settings.path_prefix}{suffix}"


def _crykeeper_url(settings: object, suffix: str, return_path: str) -> str:
  """Build a crykeeper-local URL with query parameters without relying on one endpoint name."""
  path = _crykeeper_path(settings, suffix)
  return f"{path}?{urlencode({'return': return_path})}"


def _bypass_metric_reason(reason: str) -> str:
  """Collapse configured bypass details into low-cardinality metric labels."""
  return reason.split(":", 1)[0]


def _verification_metric_outcome(result: object) -> str:
  """Map provider results to one stable outcome vocabulary for metrics."""
  if result.success:
    return "success"
  if result.retryable:
    return "retryable_failure"
  if result.error_key == "error_incomplete":
    return "incomplete"
  return "failed"


def _verification_metric_reason(result: object) -> str:
  """Expose only low-cardinality verification reasons in metrics."""
  if result.success:
    return "none"
  return result.error_key or ("retryable" if result.retryable else "failed")
