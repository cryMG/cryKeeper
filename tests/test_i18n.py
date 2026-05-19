import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from werkzeug.datastructures import LanguageAccept

import app.i18n as i18n


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


if __name__ == "__main__":
  unittest.main()
