import logging

from flask import Flask
from werkzeug.middleware.proxy_fix import ProxyFix

from .config import (
  ENFORCEMENT_MODE_CHALLENGE_PASSTHROUGH,
  ENFORCEMENT_MODE_LOG_ONLY,
  ENFORCEMENT_MODES,
  INTERNAL_OBSERVABILITY_PATH,
  load_settings_bundle,
)
from .i18n import validate_catalogs
from .observability import CryKeeperObservability, observability
from .proxy import TrustedProxyHeadersMiddleware
from .ratelimit import create_rate_limiter
from .routes import crykeeper


def create_app() -> Flask:
  """Create and validate the Flask application used by nginx auth_request."""
  app = Flask(__name__)
  settings_bundle = load_settings_bundle()
  settings = settings_bundle.default_settings
  validate_catalogs()

  if settings.rate_limit_backend not in {"auto", "memory", "valkey"}:
    raise RuntimeError(
      "CRYKEEPER_RATE_LIMIT_BACKEND must be one of 'auto', 'memory', or 'valkey'."
    )

  for context_label, effective_settings in _iter_configured_settings(settings_bundle):
    _validate_effective_settings(settings, effective_settings, context_label)

  app.config["SETTINGS"] = settings
  app.config["SETTINGS_BUNDLE"] = settings_bundle
  app.logger.setLevel(getattr(logging, settings.log_level, logging.INFO))
  wsgi_app = app.wsgi_app
  if settings.trusted_proxy_hops > 0:
    wsgi_app = ProxyFix(
      wsgi_app,
      x_for=settings.trusted_proxy_hops,
      x_proto=settings.trusted_proxy_hops,
    )
  if settings.trusted_proxy_cidrs:
    wsgi_app = TrustedProxyHeadersMiddleware(wsgi_app, settings.trusted_proxy_cidrs)
  app.wsgi_app = wsgi_app
  observability_extension = CryKeeperObservability()
  app.extensions["crykeeper_observability"] = observability_extension
  app.extensions["crykeeper_rate_limiter"] = create_rate_limiter(
    settings_bundle,
    app.logger,
    backend_failure_callback=observability_extension.record_rate_limit_backend_failure,
  )
  app.register_blueprint(observability, url_prefix=INTERNAL_OBSERVABILITY_PATH)
  for index, path_prefix in enumerate(settings_bundle.path_prefixes):
    register_options = {"url_prefix": path_prefix}
    if index > 0:
      register_options["name"] = f"crykeeper_site_{index}"
    app.register_blueprint(crykeeper, **register_options)

  if settings.cookie_binding_mode == "none":
    app.logger.warning(
      "human_cookie_binding=none allows copied cookies to be replayed from other clients."
    )

  if settings.enforcement_mode == ENFORCEMENT_MODE_LOG_ONLY:
    app.logger.warning(
      "enforcement_mode=log_only logs would-challenge decisions during GET /check but still allows the protected request through. Disable it after validating your rollout."
    )

  if settings.enforcement_mode == ENFORCEMENT_MODE_CHALLENGE_PASSTHROUGH:
    app.logger.warning(
      "enforcement_mode=challenge_passthrough still shows the challenge, but failed verification attempts issue a signed passthrough cookie instead of blocking access. Disable it after validating your rollout."
    )

  if (
    settings.cookie_binding_mode == "ip-user-agent" and settings.trusted_proxy_hops == 0
  ):
    app.logger.warning(
      "human_cookie_binding=ip-user-agent uses the direct peer address unless trusted_proxy_hops is set for your reverse-proxy chain."
    )

  if settings.real_captcha_enabled and not settings.cookie_secure:
    if not settings.allow_insecure_local_cap:
      raise RuntimeError(
        "Real captcha verification modes require CRYKEEPER_HUMAN_COOKIE_SECURE=true unless CRYKEEPER_ALLOW_INSECURE_LOCAL_CAP=true is set for local-only HTTP testing."
      )

  if settings.cookie_secure and not settings.host_cookie_enabled:
    app.logger.warning(
      "human_cookie_name does not use a '__Host-' prefix. Prefer a __Host- cookie when possible."
    )

  for context_label, effective_settings in _iter_configured_settings(settings_bundle):
    if context_label == "defaults":
      continue
    _log_website_specific_warnings(app, settings, effective_settings, context_label)

  return app


def _iter_configured_settings(settings_bundle: object):
  """Yield the shared defaults first and then each website-specific effective config."""
  yield "defaults", settings_bundle.default_settings
  for website in settings_bundle.websites:
    label = f"website[{', '.join(website.domains)}]"
    yield label, website.settings


def _validate_effective_settings(
  default_settings: object, settings: object, context_label: str
) -> None:
  """Fail fast when one effective config layer would boot into an invalid state."""
  prefix = _context_prefix(context_label)

  if settings.verification_mode not in {"dummy", "cap", "hcaptcha", "altcha"}:
    raise RuntimeError(
      f"{prefix}CRYKEEPER_VERIFICATION_MODE must be one of 'dummy', 'cap', 'hcaptcha', or 'altcha'."
    )

  if settings.enforcement_mode not in ENFORCEMENT_MODES:
    raise RuntimeError(
      f"{prefix}CRYKEEPER_ENFORCEMENT_MODE must be one of 'enforce', 'log_only', or 'challenge_passthrough'."
    )

  if settings.cookie_binding_mode not in {"none", "user-agent", "ip-user-agent"}:
    raise RuntimeError(
      f"{prefix}CRYKEEPER_HUMAN_COOKIE_BINDING must be one of 'none', 'user-agent', or 'ip-user-agent'."
    )

  if settings.secret_key in {"change-me-in-production", "dev-secret-change-me"}:
    raise RuntimeError(
      f"{prefix}CRYKEEPER_SECRET_KEY is still using the development default. Configure a unique secret before startup."
    )

  if settings.trusted_proxy_hops > 0 and not settings.trusted_proxy_cidrs:
    raise RuntimeError(
      f"{prefix}CRYKEEPER_TRUSTED_PROXY_HOPS requires a non-empty CRYKEEPER_TRUSTED_PROXY_CIDRS so forwarded headers are accepted only from trusted proxy networks."
    )

  if settings.cap_enabled and not settings.cap_configured:
    raise RuntimeError(
      f"{prefix}CAP mode requires CRYKEEPER_CAP_PUBLIC_BASE_URL, CRYKEEPER_CAP_SITE_KEY, "
      "and CRYKEEPER_CAP_SECRET_KEY to be set. CRYKEEPER_CAP_INTERNAL_BASE_URL is optional "
      "and falls back to the public URL."
    )

  if settings.hcaptcha_enabled and not settings.hcaptcha_configured:
    raise RuntimeError(
      f"{prefix}hCaptcha mode requires CRYKEEPER_HCAPTCHA_SITE_KEY and "
      "CRYKEEPER_HCAPTCHA_SECRET_KEY. CRYKEEPER_HCAPTCHA_SCRIPT_URL and "
      "CRYKEEPER_HCAPTCHA_VERIFY_URL default to the official hCaptcha endpoints."
    )

  if settings.altcha_enabled and not settings.altcha_configured:
    raise RuntimeError(
      f"{prefix}ALTCHA mode requires CRYKEEPER_ALTCHA_HMAC_SECRET. "
      "CRYKEEPER_ALTCHA_SCRIPT_URL is optional and otherwise defaults to the bundled crykeeper widget script."
    )

  if settings.altcha_enabled and settings.altcha_challenge_cost < 1:
    raise RuntimeError(
      f"{prefix}CRYKEEPER_ALTCHA_CHALLENGE_COST must be greater than 0 in ALTCHA mode."
    )

  if settings.altcha_enabled and settings.altcha_expires_seconds < 1:
    raise RuntimeError(
      f"{prefix}CRYKEEPER_ALTCHA_EXPIRES_SECONDS must be greater than 0 in ALTCHA mode."
    )

  if (
    default_settings.rate_limit_backend == "valkey"
    and not default_settings.rate_limit_valkey_url
  ):
    raise RuntimeError(
      f"{prefix}CRYKEEPER_RATE_LIMIT_BACKEND=valkey requires a non-empty CRYKEEPER_RATE_LIMIT_VALKEY_URL "
      "or shared rate_limit_valkey_url under [crykeeper]."
    )

  if (
    settings.real_captcha_enabled
    and not settings.cookie_secure
    and not settings.allow_insecure_local_cap
  ):
    raise RuntimeError(
      f"{prefix}Real captcha verification modes require CRYKEEPER_HUMAN_COOKIE_SECURE=true unless "
      "CRYKEEPER_ALLOW_INSECURE_LOCAL_CAP=true is set for local-only HTTP testing."
    )


def _log_website_specific_warnings(
  app: Flask,
  default_settings: object,
  settings: object,
  context_label: str,
) -> None:
  """Emit only those warnings that differ from the already-logged shared defaults."""
  prefix = _context_prefix(context_label)

  if (
    settings.cookie_binding_mode == "none"
    and settings.cookie_binding_mode != default_settings.cookie_binding_mode
  ):
    app.logger.warning(
      "%shuman_cookie_binding=none allows copied cookies to be replayed from other clients.",
      prefix,
    )

  if (
    settings.enforcement_mode == ENFORCEMENT_MODE_LOG_ONLY
    and settings.enforcement_mode != default_settings.enforcement_mode
  ):
    app.logger.warning(
      "%senforcement_mode=log_only logs would-challenge decisions during GET /check but still allows the protected request through. Disable it after validating your rollout.",
      prefix,
    )

  if (
    settings.enforcement_mode == ENFORCEMENT_MODE_CHALLENGE_PASSTHROUGH
    and settings.enforcement_mode != default_settings.enforcement_mode
  ):
    app.logger.warning(
      "%senforcement_mode=challenge_passthrough still shows the challenge, but failed verification attempts issue a signed passthrough cookie instead of blocking access. Disable it after validating your rollout.",
      prefix,
    )

  if (
    settings.cookie_secure
    and not settings.host_cookie_enabled
    and (
      settings.cookie_secure != default_settings.cookie_secure
      or settings.cookie_name != default_settings.cookie_name
    )
  ):
    app.logger.warning(
      "%shuman_cookie_name does not use a '__Host-' prefix. Prefer a __Host- cookie when possible.",
      prefix,
    )


def _context_prefix(context_label: str) -> str:
  """Prefix validation and warning messages with the website scope when needed."""
  return "" if context_label == "defaults" else f"{context_label}: "
