import os
import re
import tomllib
from dataclasses import dataclass, field
from ipaddress import ip_network
from pathlib import Path
from typing import Any, Mapping

from .i18n import DEFAULT_LOCALE, normalize_locale_name

ENV_PREFIX = "CRYKEEPER_"
DEFAULT_PATH_PREFIX = "/crykeeper"
DEFAULT_CONFIG_FILE = "/app/config.toml"
DEFAULT_HCAPTCHA_SCRIPT_URL = "https://js.hcaptcha.com/1/api.js?render=explicit"
DEFAULT_HCAPTCHA_VERIFY_URL = "https://api.hcaptcha.com/siteverify"
DEFAULT_ALTCHA_SCRIPT_URL = ""
DEFAULT_ALTCHA_SCRIPT_PATH = "/static/vendor/altcha.min.js"
DEFAULT_ALTCHA_ALGORITHM = "PBKDF2/SHA-256"
DEFAULT_COOKIE_NAME = "crykeeper_verified"
DEFAULT_HOST_COOKIE_NAME = "__Host-crykeeper_verified"
ENFORCEMENT_MODE_ENFORCE = "enforce"
ENFORCEMENT_MODE_LOG_ONLY = "log_only"
ENFORCEMENT_MODE_CHALLENGE_PASSTHROUGH = "challenge_passthrough"
ENFORCEMENT_MODES = frozenset(
  {
    ENFORCEMENT_MODE_ENFORCE,
    ENFORCEMENT_MODE_LOG_ONLY,
    ENFORCEMENT_MODE_CHALLENGE_PASSTHROUGH,
  }
)
DEFAULT_RATE_LIMIT_VALKEY_PREFIX = "crykeeper:rl"
DEFAULT_FOOTER_HTML = 'Powered by <a href="https://github.com/cryMG/cryKeeper" target="_blank" rel="noopener noreferrer">cryKeeper</a> - The open-source human verification service making bots cry.'
MIN_BYPASS_HEADER_TOKEN_LENGTH = 32
INTERNAL_OBSERVABILITY_PATH = "/_crykeeper"
INTERNAL_CHECK_PATH = "/_crykeeper_check"
CONFIG_TABLE_NAME = "crykeeper"
WEBSITE_TABLE_NAME = "website"
CONFIGURABLE_ENV_SUFFIXES = (
  "SECRET_KEY",
  "PREVIOUS_SECRET_KEYS",
  "HUMAN_COOKIE_NAME",
  "HUMAN_COOKIE_TTL_SECONDS",
  "HUMAN_COOKIE_SECURE",
  "ENFORCEMENT_MODE",
  "ALLOW_INSECURE_LOCAL_CAP",
  "HUMAN_COOKIE_BINDING",
  "TRUSTED_PROXY_HOPS",
  "TRUSTED_PROXY_CIDRS",
  "LOG_LEVEL",
  "ANONYMIZE_CLIENT_IP_LOGS",
  "ANONYMIZE_IPV4_PREFIX_LENGTH",
  "ANONYMIZE_IPV6_PREFIX_LENGTH",
  "VERIFICATION_MODE",
  "CAP_PUBLIC_BASE_URL",
  "CAP_INTERNAL_BASE_URL",
  "CAP_ASSET_BASE_URL",
  "CAP_SITE_KEY",
  "CAP_SECRET_KEY",
  "CAP_VERIFY_TIMEOUT_SECONDS",
  "HCAPTCHA_SCRIPT_URL",
  "HCAPTCHA_SITE_KEY",
  "HCAPTCHA_SECRET_KEY",
  "HCAPTCHA_VERIFY_URL",
  "HCAPTCHA_VERIFY_TIMEOUT_SECONDS",
  "ALTCHA_SCRIPT_URL",
  "ALTCHA_HMAC_SECRET",
  "ALTCHA_HMAC_KEY_SECRET",
  "ALTCHA_ALGORITHM",
  "ALTCHA_CHALLENGE_COST",
  "ALTCHA_EXPIRES_SECONDS",
  "CHALLENGE_RATE_LIMIT_REQUESTS",
  "CHALLENGE_RATE_LIMIT_WINDOW_SECONDS",
  "CHALLENGE_RATE_LIMIT_BLOCK_SECONDS",
  "VERIFY_RATE_LIMIT_REQUESTS",
  "VERIFY_RATE_LIMIT_WINDOW_SECONDS",
  "VERIFY_RATE_LIMIT_BLOCK_SECONDS",
  "RATE_LIMIT_BACKEND",
  "RATE_LIMIT_VALKEY_URL",
  "RATE_LIMIT_VALKEY_PREFIX",
  "RATE_LIMIT_MAX_ENTRIES",
  "MAX_RETURN_PATH_LENGTH",
  "FOOTER_HTML",
  "SKIP_ROUTES",
  "BYPASS_USER_AGENTS",
  "BYPASS_IPS",
  "BYPASS_HEADERS",
  "ALLOW_KNOWN_SEARCH_ENGINES",
  "PATH_PREFIX",
)
KNOWN_CONFIG_KEYS = frozenset(name.lower() for name in CONFIGURABLE_ENV_SUFFIXES)
NON_WEBSITE_OVERRIDE_SUFFIXES = (
  "TRUSTED_PROXY_HOPS",
  "TRUSTED_PROXY_CIDRS",
  "LOG_LEVEL",
  "ANONYMIZE_CLIENT_IP_LOGS",
  "ANONYMIZE_IPV4_PREFIX_LENGTH",
  "ANONYMIZE_IPV6_PREFIX_LENGTH",
  "RATE_LIMIT_BACKEND",
  "RATE_LIMIT_VALKEY_URL",
  "RATE_LIMIT_VALKEY_PREFIX",
  "RATE_LIMIT_MAX_ENTRIES",
)
NON_WEBSITE_OVERRIDE_KEYS = frozenset(
  name.lower() for name in NON_WEBSITE_OVERRIDE_SUFFIXES
)
HTTP_METHOD_NAME_PATTERN = re.compile(r"^[A-Z-]+$")
HEADER_NAME_PATTERN = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")


def normalize_host_name(value: str | None) -> str:
  """Normalize host names for request matching and website domain lookup."""
  host = (value or "").strip().lower()
  if not host:
    return ""

  if host.count(":") > 1 and not host.startswith("["):
    return host

  if host.startswith("["):
    return host.split("]", 1)[0].lstrip("[")

  return host.split(":", 1)[0]


def _env_name(name: str) -> str:
  """Build the preferred cryKeeper environment variable name for one setting."""
  return f"{ENV_PREFIX}{name}"


def _config_key(name: str) -> str:
  """Map one cryKeeper environment variable name to its lowercase TOML key."""
  if name.startswith(ENV_PREFIX):
    return name.removeprefix(ENV_PREFIX).lower()
  raise RuntimeError(f"{name} is not a cryKeeper setting.")


def config_option_label(name: str) -> str:
  """Return the canonical TOML key shown in user-visible config messages."""
  if name.startswith(ENV_PREFIX):
    key = name.removeprefix(ENV_PREFIX).lower()
    if key in KNOWN_CONFIG_KEYS:
      return key
  return name


def _read_config_file_path() -> Path:
  """Resolve the configured TOML file path, falling back to the container default."""
  raw_value = os.getenv(_env_name("CONFIG_FILE"), DEFAULT_CONFIG_FILE)
  value = (raw_value or "").strip() or DEFAULT_CONFIG_FILE
  return Path(value).expanduser()


@dataclass(frozen=True)
class WebsiteConfig:
  """Raw TOML override block for one set of hostnames."""

  domains: tuple[str, ...]
  file_values: Mapping[str, Any]


@dataclass(frozen=True)
class ConfigDocument:
  """Parsed config file split into shared defaults and website-specific blocks."""

  default_file_values: Mapping[str, Any]
  websites: tuple[WebsiteConfig, ...]

  @classmethod
  def load(cls) -> "ConfigDocument":
    return _load_config_document()


def _load_config_document() -> ConfigDocument:
  """Load and validate the optional TOML config file into a structured document."""
  config_path = _read_config_file_path()
  if not config_path.exists():
    return ConfigDocument(default_file_values={}, websites=())

  if not config_path.is_file():
    raise RuntimeError(
      f"{_env_name('CONFIG_FILE')} must point to a readable TOML file."
    )

  try:
    with config_path.open("rb") as config_file:
      document = tomllib.load(config_file)
  except tomllib.TOMLDecodeError as exc:
    raise RuntimeError(f"Failed to parse config file {config_path}: {exc}") from exc
  except OSError as exc:
    raise RuntimeError(f"Failed to read config file {config_path}: {exc}") from exc

  return ConfigDocument(
    default_file_values=_load_default_table(document, config_path),
    websites=_load_website_tables(document, config_path),
  )


def _load_default_table(
  document: Mapping[str, Any], config_path: Path
) -> dict[str, Any]:
  """Validate and return the shared [crykeeper] defaults from the TOML document."""
  raw_table = document.get(CONFIG_TABLE_NAME, {})
  if raw_table is None:
    return {}

  if not isinstance(raw_table, dict):
    raise RuntimeError(
      f"Config file {config_path} entry [{CONFIG_TABLE_NAME}] must be a table."
    )

  unknown_keys = sorted(set(raw_table) - KNOWN_CONFIG_KEYS)
  if unknown_keys:
    raise RuntimeError(
      f"Config file {config_path} contains unknown keys in [{CONFIG_TABLE_NAME}]: "
      f"{', '.join(unknown_keys)}."
    )

  return dict(raw_table)


def _load_website_tables(
  document: Mapping[str, Any],
  config_path: Path,
) -> tuple[WebsiteConfig, ...]:
  """Validate and return all optional [[website]] override blocks from the TOML document."""
  raw_websites = document.get(WEBSITE_TABLE_NAME)
  if raw_websites is None:
    return ()

  if not isinstance(raw_websites, list):
    raise RuntimeError(
      f"Config file {config_path} entry [[{WEBSITE_TABLE_NAME}]] must be an array of tables."
    )

  seen_domains: dict[str, int] = {}
  websites: list[WebsiteConfig] = []
  for index, raw_website in enumerate(raw_websites, start=1):
    if not isinstance(raw_website, dict):
      raise RuntimeError(
        f"Config file {config_path} entry [[{WEBSITE_TABLE_NAME}]] #{index} must be a table."
      )

    unknown_keys = sorted(set(raw_website) - KNOWN_CONFIG_KEYS - {"domains"})
    if unknown_keys:
      raise RuntimeError(
        f"Config file {config_path} contains unknown keys in "
        f"[[{WEBSITE_TABLE_NAME}]] #{index}: {', '.join(unknown_keys)}."
      )

    disallowed_keys = sorted(set(raw_website) & NON_WEBSITE_OVERRIDE_KEYS)
    if disallowed_keys:
      raise RuntimeError(
        f"Config file {config_path} may not override {', '.join(disallowed_keys)} "
        f"inside [[{WEBSITE_TABLE_NAME}]] #{index}."
      )

    domains = _read_website_domains(raw_website.get("domains"), config_path, index)
    for domain in domains:
      previous_index = seen_domains.get(domain)
      if previous_index is not None:
        raise RuntimeError(
          f"Config file {config_path} contains duplicate domain '{domain}' in "
          f"[[{WEBSITE_TABLE_NAME}]] #{previous_index} and [[{WEBSITE_TABLE_NAME}]] #{index}."
        )
      seen_domains[domain] = index

    websites.append(
      WebsiteConfig(
        domains=domains,
        file_values={
          key: value for key, value in raw_website.items() if key != "domains"
        },
      )
    )

  return tuple(websites)


def _read_website_domains(
  raw_value: Any, config_path: Path, index: int
) -> tuple[str, ...]:
  """Validate one website block's host list and normalize each configured domain."""
  if not isinstance(raw_value, (list, tuple)):
    raise RuntimeError(
      f"Config file {config_path} entry [[{WEBSITE_TABLE_NAME}]] #{index} must define "
      "domains as a non-empty TOML array of strings."
    )

  domains: list[str] = []
  for raw_domain in raw_value:
    if not isinstance(raw_domain, str):
      raise RuntimeError(
        f"Config file {config_path} entry [[{WEBSITE_TABLE_NAME}]] #{index} domains "
        "must contain only strings."
      )

    candidate = raw_domain.strip()
    if not candidate:
      raise RuntimeError(
        f"Config file {config_path} entry [[{WEBSITE_TABLE_NAME}]] #{index} domains "
        "must not contain blank values."
      )

    if any(token in candidate for token in ("//", "/", "?", "#")):
      raise RuntimeError(
        f"Config file {config_path} entry [[{WEBSITE_TABLE_NAME}]] #{index} domains "
        "must contain host names only, without paths or schemes."
      )

    normalized_domain = normalize_host_name(candidate)
    if not normalized_domain:
      raise RuntimeError(
        f"Config file {config_path} entry [[{WEBSITE_TABLE_NAME}]] #{index} domains "
        "must contain valid host names."
      )

    if "*" in normalized_domain and not normalized_domain.startswith("*."):
      raise RuntimeError(
        f"Config file {config_path} entry [[{WEBSITE_TABLE_NAME}]] #{index} domains "
        "may use wildcard '*' only as a leading '*.' prefix."
      )

    wildcard_suffix = _wildcard_domain_suffix(normalized_domain)
    if wildcard_suffix is not None:
      if (
        not wildcard_suffix
        or "*" in wildcard_suffix
        or wildcard_suffix.startswith(".")
        or wildcard_suffix.endswith(".")
      ):
        raise RuntimeError(
          f"Config file {config_path} entry [[{WEBSITE_TABLE_NAME}]] #{index} domains "
          "must use wildcards as '*.example.com' with a non-empty domain suffix."
        )

    if normalized_domain in domains:
      raise RuntimeError(
        f"Config file {config_path} entry [[{WEBSITE_TABLE_NAME}]] #{index} contains "
        f"duplicate domain '{normalized_domain}'."
      )
    domains.append(normalized_domain)

  if not domains:
    raise RuntimeError(
      f"Config file {config_path} entry [[{WEBSITE_TABLE_NAME}]] #{index} must define "
      "at least one domain."
    )

  return tuple(domains)


def _wildcard_domain_suffix(domain_pattern: str) -> str | None:
  """Return the wildcard suffix for '*.example.com' style patterns."""
  if not domain_pattern.startswith("*."):
    return None
  return domain_pattern[2:]


def _domain_pattern_matches(host: str, domain_pattern: str) -> bool:
  """Return true when host matches either an exact or wildcard domain pattern."""
  wildcard_suffix = _wildcard_domain_suffix(domain_pattern)
  if wildcard_suffix is None:
    return host == domain_pattern

  if host == wildcard_suffix:
    return False
  return host.endswith(f".{wildcard_suffix}")


def _canonical_domain_pattern(domain_pattern: str) -> str:
  """Return one stable bucket label for exact and wildcard configured domains."""
  wildcard_suffix = _wildcard_domain_suffix(domain_pattern)
  if wildcard_suffix is None:
    return domain_pattern
  return f"+.{wildcard_suffix}"


@dataclass(frozen=True)
class ConfigSource:
  """Thin lookup wrapper used by the typed config readers."""

  file_values: Mapping[str, Any]

  def get(self, name: str, default: Any = None) -> Any:
    return self.file_values.get(_config_key(name), default)


def _collect_env_overrides() -> dict[str, Any]:
  """Collect only non-empty shared environment overrides for later normalization."""
  overrides: dict[str, Any] = {}
  for suffix in CONFIGURABLE_ENV_SUFFIXES:
    env_name = _env_name(suffix)
    raw_env_value = os.getenv(env_name)
    if raw_env_value is not None and raw_env_value.strip():
      overrides[_config_key(env_name)] = raw_env_value
  return overrides


def _strip_trailing_slash(value: str) -> str:
  """Normalize base URLs so path joining below does not produce double slashes."""
  return value.rstrip("/")


def _read_text(config_source: ConfigSource, name: str, default: str) -> str:
  """Read raw string settings from env vars or the TOML file."""
  option_name = config_option_label(name)
  raw_value = config_source.get(name)
  if raw_value is None:
    return default

  if not isinstance(raw_value, str):
    raise RuntimeError(f"{option_name} must be a string.")

  return raw_value


def _read_base_url(
  config_source: ConfigSource,
  name: str,
  default: str,
  *,
  blank_uses_default: bool = False,
) -> str:
  """Read URL-like settings while normalizing trailing slashes."""
  option_name = config_option_label(name)
  raw_value = config_source.get(name)
  if raw_value is None:
    return default

  if not isinstance(raw_value, str):
    raise RuntimeError(f"{option_name} must be a string.")

  value = raw_value.strip()
  if blank_uses_default and not value:
    return default

  return _strip_trailing_slash(value)


def _read_bool(config_source: ConfigSource, name: str, default: bool) -> bool:
  """Read relaxed boolean env vars such as true/1/yes/on."""
  option_name = config_option_label(name)
  raw_value = config_source.get(name)
  if raw_value is None:
    return default

  if isinstance(raw_value, bool):
    return raw_value

  if isinstance(raw_value, str):
    return raw_value.strip().lower() in {"1", "true", "yes", "on"}

  raise RuntimeError(f"{option_name} must be a boolean.")


def _read_int(config_source: ConfigSource, name: str, default: int) -> int:
  """Read integer env vars while keeping the caller-side defaults in one place."""
  option_name = config_option_label(name)
  raw_value = config_source.get(name)
  if raw_value is None:
    return default

  if isinstance(raw_value, bool):
    raise RuntimeError(f"{option_name} must be an integer.")

  if isinstance(raw_value, int):
    return raw_value

  if isinstance(raw_value, str):
    try:
      return int(raw_value.strip())
    except ValueError as exc:
      raise RuntimeError(f"{option_name} must be an integer.") from exc

  raise RuntimeError(f"{option_name} must be an integer.")


def _read_non_negative_int(config_source: ConfigSource, name: str, default: int) -> int:
  """Read integer env vars that may be disabled with 0 but never go below it."""
  option_name = config_option_label(name)
  value = _read_int(config_source, name, default)
  if value < 0:
    raise RuntimeError(f"{option_name} must be greater than or equal to 0.")
  return value


def _read_ipv4_prefix_length(
  config_source: ConfigSource, name: str, default: int
) -> int:
  """Read IPv4 prefix length with validation (0-32)."""
  option_name = config_option_label(name)
  value = _read_int(config_source, name, default)
  if value < 0 or value > 32:
    raise RuntimeError(f"{option_name} must be between 0 and 32.")
  return value


def _read_ipv6_prefix_length(
  config_source: ConfigSource, name: str, default: int
) -> int:
  """Read IPv6 prefix length with validation (0-128)."""
  option_name = config_option_label(name)
  value = _read_int(config_source, name, default)
  if value < 0 or value > 128:
    raise RuntimeError(f"{option_name} must be between 0 and 128.")
  return value


def _read_csv_values(config_source: ConfigSource, name: str) -> tuple[str, ...]:
  """Read comma-separated string lists while ignoring empty segments."""
  option_name = config_option_label(name)
  raw_value = config_source.get(name)
  if raw_value is None:
    return ()

  if isinstance(raw_value, str):
    return tuple(value.strip() for value in raw_value.split(",") if value.strip())

  if isinstance(raw_value, (list, tuple)):
    values: list[str] = []
    for value in raw_value:
      if not isinstance(value, str):
        raise RuntimeError(f"{option_name} must contain only string values.")
      normalized_value = value.strip()
      if normalized_value:
        values.append(normalized_value)
    return tuple(values)

  raise RuntimeError(f"{option_name} must be a comma-separated string or TOML array.")


def _read_path_prefix(config_source: ConfigSource, name: str, default: str) -> str:
  """Read and validate the public path prefix reserved for cryKeeper routes."""
  option_name = config_option_label(name)
  raw_value = config_source.get(name)
  if raw_value is None:
    return default

  if not isinstance(raw_value, str):
    raise RuntimeError(f"{option_name} must be a string.")

  value = raw_value.strip()
  if not value:
    return default

  if value == "/":
    raise RuntimeError(f"{option_name} must not be '/'.")

  if not value.startswith("/"):
    raise RuntimeError(f"{option_name} must start with '/'.")

  if value.endswith("/"):
    raise RuntimeError(f"{option_name} must not end with '/'.")

  if "?" in value or "#" in value or "//" in value:
    raise RuntimeError(
      f"{option_name} must be a clean path prefix without query strings, fragments, or double slashes."
    )

  if value == INTERNAL_OBSERVABILITY_PATH:
    raise RuntimeError(
      f"{option_name} must not be '{INTERNAL_OBSERVABILITY_PATH}' because that prefix is reserved for internal observability endpoints."
    )

  return value


def _read_cookie_name(config_source: ConfigSource, name: str, secure: bool) -> str:
  """Choose a host-scoped cookie by default once the deployment uses HTTPS."""
  option_name = config_option_label(name)
  raw_value = config_source.get(name)
  if raw_value is not None and not isinstance(raw_value, str):
    raise RuntimeError(f"{option_name} must be a string.")

  value = (raw_value or "").strip()

  if not value:
    return DEFAULT_HOST_COOKIE_NAME if secure else DEFAULT_COOKIE_NAME

  if secure and value == DEFAULT_COOKIE_NAME:
    return DEFAULT_HOST_COOKIE_NAME

  if value.startswith("__Host-") and not secure:
    raise RuntimeError(
      f"{option_name} uses a '__Host-' prefix and therefore requires human_cookie_secure=true."
    )

  return value


def _read_trusted_proxy_cidrs(
  config_source: ConfigSource, name: str
) -> tuple[str, ...]:
  """Validate trusted proxy CIDRs that are allowed to supply forwarded headers."""
  values = _read_csv_values(config_source, name)
  for value in values:
    ip_network(value, strict=False)
  return values


def _locale_fallback_chain(locale: str | None) -> tuple[str, ...]:
  """Return locale candidates ordered by specificity and English fallback."""
  candidates: list[str] = []
  for raw_locale in (locale, DEFAULT_LOCALE):
    normalized_locale = normalize_locale_name(raw_locale)
    if not normalized_locale:
      continue

    candidates.append(normalized_locale)
    base_locale = normalized_locale.split("-", 1)[0]
    if base_locale != normalized_locale:
      candidates.append(base_locale)

  return tuple(dict.fromkeys(candidates))


@dataclass(frozen=True)
class LocalizedHtml:
  """Trusted HTML that may vary by locale with English fallback."""

  default_html: str = ""
  translations: tuple[tuple[str, str], ...] = ()

  def resolve(self, locale: str | None) -> str:
    """Return the best localized HTML block for the requested locale."""
    localized_values = dict(self.translations)
    for candidate in _locale_fallback_chain(locale):
      resolved_html = localized_values.get(candidate)
      if resolved_html:
        return resolved_html
    return self.default_html

  @property
  def by_locale(self) -> dict[str, str]:
    """Expose configured localized HTML values for tests and introspection."""
    return dict(self.translations)


def _read_footer_html(config_source: ConfigSource, name: str) -> LocalizedHtml:
  """Read trusted footer HTML from a string or a locale-keyed TOML mapping."""
  option_name = config_option_label(name)
  raw_value = config_source.get(name)
  if raw_value is None:
    return LocalizedHtml()

  if isinstance(raw_value, str):
    return LocalizedHtml(default_html=raw_value.strip())

  if isinstance(raw_value, dict):
    localized_values: dict[str, str] = {}
    for raw_locale, raw_html in raw_value.items():
      if not isinstance(raw_locale, str) or not isinstance(raw_html, str):
        raise RuntimeError(
          f"{option_name} must contain only string locale keys and string HTML values."
        )

      locale = normalize_locale_name(raw_locale)
      if not locale:
        raise RuntimeError(f"{option_name} must not contain blank locale keys.")

      html_value = raw_html.strip()
      if html_value:
        localized_values[locale] = html_value

    return LocalizedHtml(translations=tuple(localized_values.items()))

  raise RuntimeError(f"{option_name} must be a string or TOML table of strings.")


def _merge_footer_html_values(base_value: Any, override_value: Any) -> Any:
  """Merge localized footer tables so website overrides may inherit English defaults."""
  if not isinstance(override_value, dict):
    return override_value

  merged_value: dict[str, Any] = {}
  if isinstance(base_value, dict):
    merged_value.update(base_value)
  elif isinstance(base_value, str) and base_value.strip():
    merged_value[DEFAULT_LOCALE] = base_value

  merged_value.update(override_value)
  return merged_value


def _merge_effective_values(
  base_values: Mapping[str, Any], override_values: Mapping[str, Any]
) -> dict[str, Any]:
  """Merge website overrides onto shared defaults with special handling for localized footer HTML."""
  effective_values = dict(base_values)
  for key, value in override_values.items():
    if key == "footer_html":
      effective_values[key] = _merge_footer_html_values(
        effective_values.get(key), value
      )
      continue

    effective_values[key] = value

  return effective_values


@dataclass(frozen=True)
class SkipRouteRule:
  """One auth bypass rule matched against the original request method and path."""

  pattern: str
  regex: re.Pattern[str] = field(repr=False, compare=False)
  method: str | None = None

  def matches(self, path: str, method: str) -> bool:
    """Return true when the rule applies to the given original request."""
    if self.method is not None and method != self.method:
      return False
    return self.regex.search(path) is not None


def _parse_skip_route_rule(value: str, name: str) -> SkipRouteRule:
  """Parse one skip_routes entry in oauth2-proxy-compatible METHOD=REGEX form."""
  option_name = config_option_label(name)
  rule_text = value.strip()
  method: str | None = None
  pattern = rule_text

  method_candidate, separator, pattern_candidate = rule_text.partition("=")
  normalized_method = method_candidate.strip().upper()
  if separator and HTTP_METHOD_NAME_PATTERN.fullmatch(normalized_method):
    method = normalized_method
    pattern = pattern_candidate.strip()
    if not pattern:
      raise RuntimeError(
        f"{option_name} contains a method-specific rule without a regex pattern."
      )

  try:
    compiled_pattern = re.compile(pattern)
  except re.error as exc:
    raise RuntimeError(
      f"{option_name} contains an invalid regex '{pattern}': {exc}."
    ) from exc

  return SkipRouteRule(pattern=pattern, method=method, regex=compiled_pattern)


def _read_skip_routes(
  config_source: ConfigSource, name: str
) -> tuple[SkipRouteRule, ...]:
  """Read auth bypass routes from a comma-separated env var or TOML string array."""
  values = _read_csv_values(config_source, name)
  return tuple(_parse_skip_route_rule(value, name) for value in values)


@dataclass(frozen=True)
class UserAgentBypassRule:
  """One user-agent regex that bypasses the auth_request cookie check."""

  pattern: str
  regex: re.Pattern[str] = field(repr=False, compare=False)

  def matches(self, user_agent: str) -> bool:
    """Return true when the configured regex matches the current user agent."""
    return self.regex.search(user_agent) is not None


def _read_bypass_user_agents(
  config_source: ConfigSource, name: str
) -> tuple[UserAgentBypassRule, ...]:
  """Read regex-based user-agent bypass rules from env vars or TOML arrays."""
  option_name = config_option_label(name)
  values = _read_csv_values(config_source, name)
  rules: list[UserAgentBypassRule] = []
  for value in values:
    try:
      compiled_pattern = re.compile(value)
    except re.error as exc:
      raise RuntimeError(
        f"{option_name} contains an invalid regex '{value}': {exc}."
      ) from exc
    rules.append(UserAgentBypassRule(pattern=value, regex=compiled_pattern))
  return tuple(rules)


@dataclass(frozen=True)
class IpBypassRule:
  """One IP or CIDR range that bypasses the auth_request cookie check."""

  value: str
  network: Any = field(repr=False, compare=False)


def _read_bypass_ips(
  config_source: ConfigSource, name: str
) -> tuple[IpBypassRule, ...]:
  """Read bypass IPs or CIDRs from env vars or TOML arrays."""
  option_name = config_option_label(name)
  values = _read_csv_values(config_source, name)
  rules: list[IpBypassRule] = []
  for value in values:
    try:
      network = ip_network(value, strict=False)
    except ValueError as exc:
      raise RuntimeError(
        f"{option_name} contains an invalid IP or CIDR '{value}'."
      ) from exc
    rules.append(IpBypassRule(value=value, network=network))
  return tuple(rules)


@dataclass(frozen=True)
class HeaderBypassRule:
  """One exact header/value pair that bypasses the auth_request cookie check."""

  header_name: str
  value: str


def _parse_bypass_header_rule(value: str, name: str) -> HeaderBypassRule:
  """Parse one header-based bypass rule in HEADER=VALUE form."""
  option_name = config_option_label(name)
  header_name, separator, header_value = value.partition("=")
  normalized_name = header_name.strip()
  normalized_value = header_value.strip()

  if not separator or not normalized_name or not normalized_value:
    raise RuntimeError(f"{option_name} entries must use non-empty HEADER=VALUE pairs.")

  if not HEADER_NAME_PATTERN.fullmatch(normalized_name):
    raise RuntimeError(
      f"{option_name} contains an invalid header name '{normalized_name}'."
    )

  if len(normalized_value) < MIN_BYPASS_HEADER_TOKEN_LENGTH:
    raise RuntimeError(
      f"{option_name} token values must be at least {MIN_BYPASS_HEADER_TOKEN_LENGTH} characters long."
    )

  return HeaderBypassRule(
    header_name=normalized_name,
    value=normalized_value,
  )


def _read_bypass_headers(
  config_source: ConfigSource, name: str
) -> tuple[HeaderBypassRule, ...]:
  """Read exact header/value bypass rules from env vars or TOML arrays."""
  values = _read_csv_values(config_source, name)
  return tuple(_parse_bypass_header_rule(value, name) for value in values)


@dataclass(frozen=True)
class Settings:
  """Effective runtime settings derived from defaults, TOML, and env vars."""

  secret_key: str
  previous_secret_keys: tuple[str, ...]
  cookie_name: str
  cookie_ttl_seconds: int
  cookie_secure: bool
  enforcement_mode: str
  allow_insecure_local_cap: bool
  cookie_binding_mode: str
  trusted_proxy_hops: int
  trusted_proxy_cidrs: tuple[str, ...]
  log_level: str
  anonymize_client_ip_logs: bool
  anonymize_ipv4_prefix_length: int
  anonymize_ipv6_prefix_length: int
  verification_mode: str
  cap_public_base_url: str
  cap_internal_base_url: str
  cap_asset_base_url: str
  cap_site_key: str
  cap_secret_key: str
  cap_verify_timeout_seconds: int
  hcaptcha_script_url: str
  hcaptcha_site_key: str
  hcaptcha_secret_key: str
  hcaptcha_verify_url: str
  hcaptcha_verify_timeout_seconds: int
  altcha_script_url: str
  altcha_hmac_secret: str
  altcha_hmac_key_secret: str
  altcha_algorithm: str
  altcha_challenge_cost: int
  altcha_expires_seconds: int
  challenge_rate_limit_requests: int
  challenge_rate_limit_window_seconds: int
  challenge_rate_limit_block_seconds: int
  verify_rate_limit_requests: int
  verify_rate_limit_window_seconds: int
  verify_rate_limit_block_seconds: int
  rate_limit_backend: str
  rate_limit_valkey_url: str
  rate_limit_valkey_prefix: str
  rate_limit_max_entries: int
  max_return_path_length: int
  footer_html: LocalizedHtml
  skip_routes: tuple[SkipRouteRule, ...]
  bypass_user_agents: tuple[UserAgentBypassRule, ...]
  bypass_ips: tuple[IpBypassRule, ...]
  bypass_headers: tuple[HeaderBypassRule, ...]
  allow_known_search_engines: bool
  path_prefix: str
  blocked_return_prefixes: tuple[str, ...]

  @property
  def host_cookie_enabled(self) -> bool:
    return self.cookie_name.startswith("__Host-")

  @property
  def all_secret_keys(self) -> tuple[str, ...]:
    ordered_keys = [self.secret_key]
    ordered_keys.extend(self.previous_secret_keys)
    return tuple(dict.fromkeys(ordered_keys))

  @property
  def cap_enabled(self) -> bool:
    return self.verification_mode == "cap"

  @property
  def hcaptcha_enabled(self) -> bool:
    return self.verification_mode == "hcaptcha"

  @property
  def altcha_enabled(self) -> bool:
    return self.verification_mode == "altcha"

  @property
  def real_captcha_enabled(self) -> bool:
    return self.verification_mode in {"cap", "hcaptcha", "altcha"}

  @property
  def cap_configured(self) -> bool:
    return all(
      (
        self.cap_public_base_url,
        self.cap_site_key,
        self.cap_secret_key,
      )
    )

  @property
  def hcaptcha_configured(self) -> bool:
    return all(
      (
        self.hcaptcha_script_url,
        self.hcaptcha_verify_url,
        self.hcaptcha_site_key,
        self.hcaptcha_secret_key,
      )
    )

  @property
  def altcha_configured(self) -> bool:
    return bool(self.altcha_effective_script_url and self.altcha_hmac_secret)

  @property
  def cap_api_endpoint(self) -> str:
    return f"{self.cap_public_base_url}/{self.cap_site_key}/"

  @property
  def cap_siteverify_url(self) -> str:
    return f"{self.cap_internal_base_url}/{self.cap_site_key}/siteverify"

  @property
  def cap_widget_script_url(self) -> str:
    return f"{self.cap_asset_base_url}/assets/widget.js"

  @property
  def cap_wasm_script_url(self) -> str:
    return f"{self.cap_asset_base_url}/assets/cap_wasm.js"

  @property
  def altcha_effective_script_url(self) -> str:
    return self.altcha_script_url or f"{self.path_prefix}{DEFAULT_ALTCHA_SCRIPT_PATH}"

  @property
  def altcha_effective_hmac_key_secret(self) -> str:
    return self.altcha_hmac_key_secret or self.altcha_hmac_secret


@dataclass(frozen=True)
class WebsiteSettings:
  """Effective runtime settings for one website block and its matched domains."""

  domains: tuple[str, ...]
  settings: Settings


@dataclass(frozen=True)
class SettingsBundle:
  """Shared defaults plus all validated per-website effective settings."""

  default_settings: Settings
  websites: tuple[WebsiteSettings, ...]

  def canonical_host(self, host: str | None) -> str:
    """Return one bounded host key for metrics and other runtime bucketing."""
    normalized_host = normalize_host_name(host)
    if not normalized_host:
      return "default"

    for website in self.websites:
      for domain_pattern in website.domains:
        if normalized_host == domain_pattern:
          return normalized_host

    for website in self.websites:
      for domain_pattern in website.domains:
        if _domain_pattern_matches(normalized_host, domain_pattern):
          return _canonical_domain_pattern(domain_pattern)

    return "default"

  def settings_for_host(self, host: str | None) -> Settings:
    """Return the effective settings that apply to the current request host."""
    normalized_host = normalize_host_name(host)
    if not normalized_host:
      return self.default_settings

    for website in self.websites:
      for domain_pattern in website.domains:
        if normalized_host == domain_pattern:
          return website.settings

    for website in self.websites:
      for domain_pattern in website.domains:
        if _domain_pattern_matches(normalized_host, domain_pattern):
          return website.settings

    return self.default_settings

  @property
  def path_prefixes(self) -> tuple[str, ...]:
    """Return every unique cryKeeper prefix that must be registered at startup."""
    prefixes = [self.default_settings.path_prefix]
    prefixes.extend(website.settings.path_prefix for website in self.websites)
    return tuple(dict.fromkeys(prefixes))


def _load_settings_from_values(values: Mapping[str, Any]) -> Settings:
  """Normalize one effective configuration layer into runtime settings."""
  config_source = ConfigSource(file_values=values)
  secret_key = _read_text(
    config_source, _env_name("SECRET_KEY"), "change-me-in-production"
  )
  cap_public_base_url = _read_base_url(
    config_source, _env_name("CAP_PUBLIC_BASE_URL"), ""
  )
  cap_internal_base_url = _read_base_url(
    config_source,
    _env_name("CAP_INTERNAL_BASE_URL"),
    cap_public_base_url,
    blank_uses_default=True,
  )
  cap_asset_base_url = _read_base_url(
    config_source,
    _env_name("CAP_ASSET_BASE_URL"),
    cap_public_base_url,
    blank_uses_default=True,
  )
  hcaptcha_script_url = (
    _read_text(
      config_source,
      _env_name("HCAPTCHA_SCRIPT_URL"),
      DEFAULT_HCAPTCHA_SCRIPT_URL,
    ).strip()
    or DEFAULT_HCAPTCHA_SCRIPT_URL
  )
  hcaptcha_verify_url = (
    _read_text(
      config_source,
      _env_name("HCAPTCHA_VERIFY_URL"),
      DEFAULT_HCAPTCHA_VERIFY_URL,
    ).strip()
    or DEFAULT_HCAPTCHA_VERIFY_URL
  )
  altcha_script_url = (
    _read_text(
      config_source,
      _env_name("ALTCHA_SCRIPT_URL"),
      DEFAULT_ALTCHA_SCRIPT_URL,
    ).strip()
    or DEFAULT_ALTCHA_SCRIPT_URL
  )
  path_prefix = _read_path_prefix(
    config_source, _env_name("PATH_PREFIX"), DEFAULT_PATH_PREFIX
  )
  cookie_secure = _read_bool(config_source, _env_name("HUMAN_COOKIE_SECURE"), False)
  return Settings(
    secret_key=secret_key,
    previous_secret_keys=tuple(
      candidate_key
      for candidate_key in dict.fromkeys(
        _read_csv_values(config_source, _env_name("PREVIOUS_SECRET_KEYS"))
      )
      if candidate_key != secret_key
    ),
    cookie_name=_read_cookie_name(
      config_source, _env_name("HUMAN_COOKIE_NAME"), cookie_secure
    ),
    cookie_ttl_seconds=_read_int(
      config_source,
      _env_name("HUMAN_COOKIE_TTL_SECONDS"),
      24 * 60 * 60,
    ),
    cookie_secure=cookie_secure,
    enforcement_mode=_read_text(
      config_source,
      _env_name("ENFORCEMENT_MODE"),
      ENFORCEMENT_MODE_ENFORCE,
    )
    .strip()
    .lower(),
    allow_insecure_local_cap=_read_bool(
      config_source,
      _env_name("ALLOW_INSECURE_LOCAL_CAP"),
      False,
    ),
    cookie_binding_mode=_read_text(
      config_source,
      _env_name("HUMAN_COOKIE_BINDING"),
      "user-agent",
    )
    .strip()
    .lower(),
    trusted_proxy_hops=_read_non_negative_int(
      config_source, _env_name("TRUSTED_PROXY_HOPS"), 0
    ),
    trusted_proxy_cidrs=_read_trusted_proxy_cidrs(
      config_source,
      _env_name("TRUSTED_PROXY_CIDRS"),
    ),
    log_level=_read_text(config_source, _env_name("LOG_LEVEL"), "INFO").upper(),
    anonymize_client_ip_logs=_read_bool(
      config_source,
      _env_name("ANONYMIZE_CLIENT_IP_LOGS"),
      True,
    ),
    anonymize_ipv4_prefix_length=_read_ipv4_prefix_length(
      config_source,
      _env_name("ANONYMIZE_IPV4_PREFIX_LENGTH"),
      24,
    ),
    anonymize_ipv6_prefix_length=_read_ipv6_prefix_length(
      config_source,
      _env_name("ANONYMIZE_IPV6_PREFIX_LENGTH"),
      48,
    ),
    verification_mode=_read_text(
      config_source,
      _env_name("VERIFICATION_MODE"),
      "dummy",
    )
    .strip()
    .lower(),
    cap_public_base_url=cap_public_base_url,
    cap_internal_base_url=cap_internal_base_url,
    cap_asset_base_url=cap_asset_base_url,
    cap_site_key=_read_text(config_source, _env_name("CAP_SITE_KEY"), "").strip(),
    cap_secret_key=_read_text(config_source, _env_name("CAP_SECRET_KEY"), "").strip(),
    cap_verify_timeout_seconds=_read_int(
      config_source, _env_name("CAP_VERIFY_TIMEOUT_SECONDS"), 5
    ),
    hcaptcha_script_url=hcaptcha_script_url,
    hcaptcha_site_key=_read_text(
      config_source, _env_name("HCAPTCHA_SITE_KEY"), ""
    ).strip(),
    hcaptcha_secret_key=_read_text(
      config_source, _env_name("HCAPTCHA_SECRET_KEY"), ""
    ).strip(),
    hcaptcha_verify_url=hcaptcha_verify_url,
    hcaptcha_verify_timeout_seconds=_read_int(
      config_source, _env_name("HCAPTCHA_VERIFY_TIMEOUT_SECONDS"), 5
    ),
    altcha_script_url=altcha_script_url,
    altcha_hmac_secret=_read_text(
      config_source, _env_name("ALTCHA_HMAC_SECRET"), ""
    ).strip(),
    altcha_hmac_key_secret=_read_text(
      config_source, _env_name("ALTCHA_HMAC_KEY_SECRET"), ""
    ).strip(),
    altcha_algorithm=(
      _read_text(
        config_source,
        _env_name("ALTCHA_ALGORITHM"),
        DEFAULT_ALTCHA_ALGORITHM,
      ).strip()
      or DEFAULT_ALTCHA_ALGORITHM
    ),
    altcha_challenge_cost=_read_non_negative_int(
      config_source, _env_name("ALTCHA_CHALLENGE_COST"), 5000
    ),
    altcha_expires_seconds=_read_non_negative_int(
      config_source, _env_name("ALTCHA_EXPIRES_SECONDS"), 300
    ),
    challenge_rate_limit_requests=_read_non_negative_int(
      config_source, _env_name("CHALLENGE_RATE_LIMIT_REQUESTS"), 20
    ),
    challenge_rate_limit_window_seconds=_read_non_negative_int(
      config_source, _env_name("CHALLENGE_RATE_LIMIT_WINDOW_SECONDS"), 60
    ),
    challenge_rate_limit_block_seconds=_read_non_negative_int(
      config_source, _env_name("CHALLENGE_RATE_LIMIT_BLOCK_SECONDS"), 120
    ),
    verify_rate_limit_requests=_read_non_negative_int(
      config_source,
      _env_name("VERIFY_RATE_LIMIT_REQUESTS"),
      10,
    ),
    verify_rate_limit_window_seconds=_read_non_negative_int(
      config_source, _env_name("VERIFY_RATE_LIMIT_WINDOW_SECONDS"), 60
    ),
    verify_rate_limit_block_seconds=_read_non_negative_int(
      config_source, _env_name("VERIFY_RATE_LIMIT_BLOCK_SECONDS"), 300
    ),
    rate_limit_backend=_read_text(
      config_source, _env_name("RATE_LIMIT_BACKEND"), "auto"
    )
    .strip()
    .lower(),
    rate_limit_valkey_url=_read_text(
      config_source, _env_name("RATE_LIMIT_VALKEY_URL"), ""
    ).strip(),
    rate_limit_valkey_prefix=_read_text(
      config_source,
      _env_name("RATE_LIMIT_VALKEY_PREFIX"),
      DEFAULT_RATE_LIMIT_VALKEY_PREFIX,
    ).strip()
    or DEFAULT_RATE_LIMIT_VALKEY_PREFIX,
    rate_limit_max_entries=_read_non_negative_int(
      config_source,
      _env_name("RATE_LIMIT_MAX_ENTRIES"),
      10000,
    ),
    max_return_path_length=_read_int(
      config_source, _env_name("MAX_RETURN_PATH_LENGTH"), 2048
    ),
    footer_html=_read_footer_html(config_source, _env_name("FOOTER_HTML")),
    skip_routes=_read_skip_routes(config_source, _env_name("SKIP_ROUTES")),
    bypass_user_agents=_read_bypass_user_agents(
      config_source, _env_name("BYPASS_USER_AGENTS")
    ),
    bypass_ips=_read_bypass_ips(config_source, _env_name("BYPASS_IPS")),
    bypass_headers=_read_bypass_headers(config_source, _env_name("BYPASS_HEADERS")),
    allow_known_search_engines=_read_bool(
      config_source, _env_name("ALLOW_KNOWN_SEARCH_ENGINES"), False
    ),
    path_prefix=path_prefix,
    blocked_return_prefixes=(
      path_prefix,
      INTERNAL_OBSERVABILITY_PATH,
      INTERNAL_CHECK_PATH,
    ),
  )


def load_settings_bundle() -> SettingsBundle:
  """Load default settings plus any TOML-only per-website overrides."""
  config_document = ConfigDocument.load()
  base_values = dict(config_document.default_file_values)
  base_values.update(_collect_env_overrides())

  default_settings = _load_settings_from_values(base_values)
  website_settings: list[WebsiteSettings] = []
  for website in config_document.websites:
    effective_values = _merge_effective_values(base_values, website.file_values)
    website_settings.append(
      WebsiteSettings(
        domains=website.domains,
        settings=_load_settings_from_values(effective_values),
      )
    )

  return SettingsBundle(
    default_settings=default_settings,
    websites=tuple(website_settings),
  )


def load_settings() -> Settings:
  """Load the default normalized settings for backward-compatible callers."""
  return load_settings_bundle().default_settings
