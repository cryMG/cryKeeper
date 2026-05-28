import json
from functools import lru_cache
from pathlib import Path
from typing import Any

DEFAULT_LOCALE = "en"
TRANSLATIONS_DIR = Path(__file__).with_name("i18n")
REQUIRED_TRANSLATION_KEYS = (
  "page_title",
  "eyebrow",
  "headline",
  "body",
  "noscript_required",
  "dummy_notice",
  "dummy_continue",
  "progress_label",
  "progress_idle",
  "progress_checking",
  "progress_verifying",
  "progress_complete",
  "dummy_progress_running",
  "retry_button",
  "reload_button",
  "error_incomplete",
  "error_failed",
  "error_unavailable",
  "error_rate_limited",
  "error_insecure_transport",
  "error_widget_load",
  "error_widget_runtime",
  "status_dummy_ready",
  "status_hcaptcha_ready",
  "status_altcha_ready",
  "status_retry_ready",
  "status_reload_ready",
)


def normalize_locale_name(value: str | None) -> str:
  """Normalize locale identifiers so file names and request headers compare consistently."""
  return (value or "").strip().replace("_", "-").lower()


@lru_cache(maxsize=None)
def _catalog_paths() -> dict[str, Path]:
  """Return the discovered translation catalogs keyed by normalized locale."""
  catalog_paths: dict[str, Path] = {}
  for catalog_path in sorted(TRANSLATIONS_DIR.glob("*.json")):
    locale = normalize_locale_name(catalog_path.stem)
    if not locale:
      raise RuntimeError(
        f"Translation catalog {catalog_path.name} must have a non-empty locale name."
      )

    previous_path = catalog_paths.get(locale)
    if previous_path is not None:
      raise RuntimeError(
        f"Translation catalogs {previous_path.name} and {catalog_path.name} resolve to the same locale '{locale}'."
      )

    catalog_paths[locale] = catalog_path

  return catalog_paths


@lru_cache(maxsize=None)
def available_locales() -> tuple[str, ...]:
  """Return the locales discovered from JSON catalogs present at startup."""
  return tuple(_catalog_paths())


@lru_cache(maxsize=None)
def _load_catalog(locale: str) -> dict[str, str]:
  """Load one locale catalog from disk and keep it cached for future requests."""
  normalized_locale = normalize_locale_name(locale)
  catalog_path = _catalog_paths().get(normalized_locale)
  if catalog_path is None:
    raise RuntimeError(
      f"Translation catalog for locale '{normalized_locale}' was not found in {TRANSLATIONS_DIR}."
    )

  with catalog_path.open("r", encoding="utf-8") as file_handle:
    catalog = json.load(file_handle)

  if not isinstance(catalog, dict) or not all(
    isinstance(key, str) and isinstance(value, str) for key, value in catalog.items()
  ):
    raise RuntimeError(
      f"Translation catalog {catalog_path.name} must contain string keys and values."
    )

  return catalog


def validate_catalogs() -> None:
  """Fail fast at startup if translation files are missing, malformed, or incomplete."""
  locales = available_locales()
  if DEFAULT_LOCALE not in locales:
    raise RuntimeError(
      f"Default translation catalog {DEFAULT_LOCALE}.json is required in {TRANSLATIONS_DIR}."
    )

  default_catalog = _load_catalog(DEFAULT_LOCALE)
  missing_default_keys = [
    key for key in REQUIRED_TRANSLATION_KEYS if key not in default_catalog
  ]
  if missing_default_keys:
    raise RuntimeError(
      "Default translation catalog is missing required keys: "
      + ", ".join(sorted(missing_default_keys))
    )

  for locale in locales:
    _load_catalog(locale)


def select_locale(accept_languages: Any) -> str:
  """Choose the best supported locale from the request's Accept-Language header."""
  match = accept_languages.best_match(available_locales())
  return normalize_locale_name(match) or DEFAULT_LOCALE


def get_translations(accept_languages: Any) -> tuple[str, dict[str, str]]:
  """Return the selected locale and a catalog merged with English fallback strings."""
  locale = select_locale(accept_languages)
  default_catalog = _load_catalog(DEFAULT_LOCALE)
  if locale == DEFAULT_LOCALE:
    return locale, default_catalog

  localized_catalog = default_catalog.copy()
  localized_catalog.update(_load_catalog(locale))
  return locale, localized_catalog
