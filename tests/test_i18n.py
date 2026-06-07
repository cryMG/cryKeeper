import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import app.i18n as i18n
from werkzeug.datastructures import LanguageAccept


class TranslationDiscoveryTests(unittest.TestCase):
  def _clear_caches(self) -> None:
    i18n.available_locales.cache_clear()
    i18n._catalog_paths.cache_clear()
    i18n._load_catalog.cache_clear()

  def _write_catalog(
    self, directory: str, locale: str, contents: dict[str, str]
  ) -> None:
    catalog_path = Path(directory) / f"{locale}.json"
    catalog_path.write_text(json.dumps(contents), encoding="utf-8")

  def _english_catalog(self) -> dict[str, str]:
    return {key: f"english {key}" for key in i18n.REQUIRED_TRANSLATION_KEYS}

  def setUp(self) -> None:
    self._clear_caches()

  def tearDown(self) -> None:
    self._clear_caches()

  def test_validate_catalogs_discovers_locales_from_present_json_files(self):
    with tempfile.TemporaryDirectory() as temp_dir:
      self._write_catalog(temp_dir, "en", self._english_catalog())
      self._write_catalog(temp_dir, "fr", {"headline": "bonjour"})

      with patch.object(i18n, "TRANSLATIONS_DIR", Path(temp_dir)):
        i18n.validate_catalogs()

        self.assertEqual(("en", "fr"), i18n.available_locales())

  def test_validate_catalogs_requires_default_english_catalog(self):
    with tempfile.TemporaryDirectory() as temp_dir:
      self._write_catalog(temp_dir, "de", {"headline": "hallo"})

      with patch.object(i18n, "TRANSLATIONS_DIR", Path(temp_dir)):
        with self.assertRaisesRegex(RuntimeError, "en.json is required"):
          i18n.validate_catalogs()

  def test_validate_catalogs_rejects_locale_name_collisions_after_normalization(self):
    with tempfile.TemporaryDirectory() as temp_dir:
      self._write_catalog(temp_dir, "en", self._english_catalog())
      self._write_catalog(temp_dir, "pt-BR", {"headline": "ola"})
      self._write_catalog(temp_dir, "pt_br", {"headline": "oi"})

      with patch.object(i18n, "TRANSLATIONS_DIR", Path(temp_dir)):
        with self.assertRaisesRegex(RuntimeError, "resolve to the same locale 'pt-br'"):
          i18n.validate_catalogs()

  def test_get_translations_uses_discovered_locale_with_english_fallback(self):
    with tempfile.TemporaryDirectory() as temp_dir:
      english_catalog = self._english_catalog()
      self._write_catalog(temp_dir, "en", english_catalog)
      self._write_catalog(temp_dir, "fr", {"headline": "bonjour"})

      with patch.object(i18n, "TRANSLATIONS_DIR", Path(temp_dir)):
        i18n.validate_catalogs()

        locale, catalog = i18n.get_translations(LanguageAccept([("fr", 1)]))

    self.assertEqual("fr", locale)
    self.assertEqual("bonjour", catalog["headline"])
    self.assertEqual(english_catalog["body"], catalog["body"])


class ActualTranslationFilesTests(unittest.TestCase):
  """Tests that verify all actual translation files in the project."""

  def test_all_translation_files_contain_all_required_keys(self):
    """Verify that all translation files contain all required keys from en.json."""
    translations_dir = i18n.TRANSLATIONS_DIR

    # Load the English catalog to get the required keys
    with (translations_dir / "en.json").open(encoding="utf-8") as f:
      english_catalog = json.load(f)

    required_keys = set(english_catalog.keys())

    # Find all translation files except en.json
    translation_files = [
      f for f in translations_dir.glob("*.json") if f.name != "en.json"
    ]

    missing_keys_by_locale = {}
    for translation_file in translation_files:
      locale = translation_file.stem

      with translation_file.open(encoding="utf-8") as f:
        catalog = json.load(f)

      catalog_keys = set(catalog.keys())
      missing_keys = required_keys - catalog_keys

      if missing_keys:
        missing_keys_by_locale[locale] = sorted(missing_keys)

    if missing_keys_by_locale:
      error_messages = []
      for locale, missing_keys in missing_keys_by_locale.items():
        error_messages.append(
          f"{locale}.json is missing keys: {', '.join(missing_keys)}"
        )
      self.fail("\n".join(error_messages))

  def test_all_translation_files_have_valid_json_structure(self):
    """Verify that all translation files are valid JSON with string keys and values."""
    translations_dir = i18n.TRANSLATIONS_DIR

    for translation_file in translations_dir.glob("*.json"):
      locale = translation_file.stem

      with translation_file.open(encoding="utf-8") as f:
        try:
          catalog = json.load(f)
        except json.JSONDecodeError as e:
          self.fail(f"{locale}.json is not valid JSON: {e}")

      # Verify catalog is a dictionary
      if not isinstance(catalog, dict):
        self.fail(f"{locale}.json must contain a dictionary, got {type(catalog)}")

      # Verify all keys and values are strings
      for key, value in catalog.items():
        if not isinstance(key, str):
          self.fail(f"{locale}.json has non-string key '{key}' of type {type(key)}")
        if not isinstance(value, str):
          self.fail(
            f"{locale}.json has non-string value for key '{key}' of type {type(value)}"
          )

  def test_all_translation_files_have_lang_field(self):
    """Verify that all translation files have a 'lang' field matching their locale."""
    translations_dir = i18n.TRANSLATIONS_DIR

    for translation_file in translations_dir.glob("*.json"):
      locale = translation_file.stem

      with translation_file.open(encoding="utf-8") as f:
        catalog = json.load(f)

      if "lang" not in catalog:
        self.fail(f"{locale}.json is missing 'lang' field")

      lang_value = catalog["lang"]
      expected_lang = locale.lower().replace("_", "-")

      if lang_value != expected_lang:
        self.fail(
          f"{locale}.json has 'lang' field '{lang_value}', expected '{expected_lang}'"
        )


if __name__ == "__main__":
  unittest.main()
