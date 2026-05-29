import os
import tempfile
import textwrap
import unittest
from pathlib import Path
from unittest.mock import patch

from app.config import load_settings, load_settings_bundle


class ConfigLoadingTests(unittest.TestCase):
  def _write_config(self, directory: str, contents: str) -> str:
    config_path = Path(directory) / "config.toml"
    config_path.write_text(textwrap.dedent(contents), encoding="utf-8")
    return str(config_path)

  def test_loads_settings_from_toml_file(self):
    with tempfile.TemporaryDirectory() as temp_dir:
      config_path = self._write_config(
        temp_dir,
        """
                [crykeeper]
                secret_key = "file-secret"
                human_cookie_name = "__Host-file-cookie"
                human_cookie_ttl_seconds = 123
                human_cookie_secure = true
                allow_insecure_local_cap = true
                human_cookie_binding = "none"
                trusted_proxy_hops = 2
                trusted_proxy_cidrs = ["10.0.0.0/8", "192.168.0.0/16"]
                log_level = "debug"
                verification_mode = "cap"
                cap_public_base_url = "https://cap.example.com/"
                cap_internal_base_url = ""
                cap_asset_base_url = ""
                cap_site_key = "site-key"
                cap_secret_key = "secret-key"
                cap_verify_timeout_seconds = 9
                hcaptcha_script_url = "https://js.hcaptcha.com/1/api.js?render=explicit"
                hcaptcha_site_key = "h-site-key"
                hcaptcha_secret_key = "h-secret-key"
                hcaptcha_verify_url = "https://api.hcaptcha.com/siteverify"
                hcaptcha_verify_timeout_seconds = 6
                altcha_script_url = "https://cdn.jsdelivr.net/npm/altcha/dist/main/altcha.min.js"
                altcha_hmac_secret = "altcha-secret"
                altcha_hmac_key_secret = "altcha-fast-secret"
                altcha_algorithm = "PBKDF2/SHA-512"
                altcha_challenge_cost = 6000
                altcha_expires_seconds = 180
                challenge_rate_limit_requests = 5
                challenge_rate_limit_window_seconds = 11
                challenge_rate_limit_block_seconds = 17
                verify_rate_limit_requests = 3
                verify_rate_limit_window_seconds = 7
                verify_rate_limit_block_seconds = 13
                rate_limit_backend = "valkey"
                rate_limit_valkey_url = "redis://valkey:6379/1"
                rate_limit_valkey_prefix = "custom-prefix"
                rate_limit_max_entries = 55
                max_return_path_length = 512
                footer_html = { en = 'powered by <strong>cryMG</strong>', de = 'bereitgestellt von <strong>cryMG</strong>' }
                skip_routes = ["^/public/", "GET=^/assets/", "POST=^/api/"]
                bypass_user_agents = ["^TestBot/.*$", "(?i)friendlycrawler"]
                bypass_ips = ["203.0.113.10", "2001:db8::/32"]
                allow_known_search_engines = true
                path_prefix = "/human-check"
                """,
      )

      with patch.dict(os.environ, {"CRYKEEPER_CONFIG_FILE": config_path}, clear=True):
        settings = load_settings()

    self.assertEqual("file-secret", settings.secret_key)
    self.assertEqual("__Host-file-cookie", settings.cookie_name)
    self.assertEqual(123, settings.cookie_ttl_seconds)
    self.assertTrue(settings.cookie_secure)
    self.assertTrue(settings.allow_insecure_local_cap)
    self.assertEqual("none", settings.cookie_binding_mode)
    self.assertEqual(2, settings.trusted_proxy_hops)
    self.assertEqual(("10.0.0.0/8", "192.168.0.0/16"), settings.trusted_proxy_cidrs)
    self.assertEqual("DEBUG", settings.log_level)
    self.assertEqual("cap", settings.verification_mode)
    self.assertEqual("https://cap.example.com", settings.cap_public_base_url)
    self.assertEqual("https://cap.example.com", settings.cap_internal_base_url)
    self.assertEqual("https://cap.example.com", settings.cap_asset_base_url)
    self.assertEqual("site-key", settings.cap_site_key)
    self.assertEqual("secret-key", settings.cap_secret_key)
    self.assertEqual(9, settings.cap_verify_timeout_seconds)
    self.assertEqual(
      "https://js.hcaptcha.com/1/api.js?render=explicit",
      settings.hcaptcha_script_url,
    )
    self.assertEqual("h-site-key", settings.hcaptcha_site_key)
    self.assertEqual("h-secret-key", settings.hcaptcha_secret_key)
    self.assertEqual(
      "https://api.hcaptcha.com/siteverify", settings.hcaptcha_verify_url
    )
    self.assertEqual(6, settings.hcaptcha_verify_timeout_seconds)
    self.assertEqual(
      "https://cdn.jsdelivr.net/npm/altcha/dist/main/altcha.min.js",
      settings.altcha_script_url,
    )
    self.assertEqual(
      "https://cdn.jsdelivr.net/npm/altcha/dist/main/altcha.min.js",
      settings.altcha_effective_script_url,
    )
    self.assertEqual("altcha-secret", settings.altcha_hmac_secret)
    self.assertEqual("altcha-fast-secret", settings.altcha_hmac_key_secret)
    self.assertEqual("PBKDF2/SHA-512", settings.altcha_algorithm)
    self.assertEqual(6000, settings.altcha_challenge_cost)
    self.assertEqual(180, settings.altcha_expires_seconds)
    self.assertEqual(5, settings.challenge_rate_limit_requests)
    self.assertEqual(11, settings.challenge_rate_limit_window_seconds)
    self.assertEqual(17, settings.challenge_rate_limit_block_seconds)
    self.assertEqual(3, settings.verify_rate_limit_requests)
    self.assertEqual(7, settings.verify_rate_limit_window_seconds)
    self.assertEqual(13, settings.verify_rate_limit_block_seconds)
    self.assertEqual("valkey", settings.rate_limit_backend)
    self.assertEqual("redis://valkey:6379/1", settings.rate_limit_valkey_url)
    self.assertEqual("custom-prefix", settings.rate_limit_valkey_prefix)
    self.assertEqual(55, settings.rate_limit_max_entries)
    self.assertEqual(512, settings.max_return_path_length)
    self.assertEqual(
      "bereitgestellt von <strong>cryMG</strong>", settings.footer_html.resolve("de")
    )
    self.assertEqual(
      "powered by <strong>cryMG</strong>", settings.footer_html.resolve("fr")
    )
    self.assertEqual(
      {
        "en": "powered by <strong>cryMG</strong>",
        "de": "bereitgestellt von <strong>cryMG</strong>",
      },
      settings.footer_html.by_locale,
    )
    self.assertEqual(
      ((None, "^/public/"), ("GET", "^/assets/"), ("POST", "^/api/")),
      tuple((rule.method, rule.pattern) for rule in settings.skip_routes),
    )
    self.assertEqual(
      ("^TestBot/.*$", "(?i)friendlycrawler"),
      tuple(rule.pattern for rule in settings.bypass_user_agents),
    )
    self.assertEqual(
      ("203.0.113.10", "2001:db8::/32"),
      tuple(rule.value for rule in settings.bypass_ips),
    )
    self.assertTrue(settings.allow_known_search_engines)
    self.assertEqual("/human-check", settings.path_prefix)

  def test_environment_variables_override_toml_settings(self):
    with tempfile.TemporaryDirectory() as temp_dir:
      config_path = self._write_config(
        temp_dir,
        """
                [crykeeper]
                secret_key = "file-secret"
                human_cookie_ttl_seconds = 321
                human_cookie_secure = true
                footer_html = "from file"
                skip_routes = ["^/file-only/"]
                bypass_user_agents = ["^FileBot$"]
                bypass_ips = ["203.0.113.0/24"]
                allow_known_search_engines = false
                trusted_proxy_cidrs = ["10.0.0.0/8"]
                rate_limit_backend = "memory"
                path_prefix = "/from-file"
                """,
      )

      with patch.dict(
        os.environ,
        {
          "CRYKEEPER_CONFIG_FILE": config_path,
          "CRYKEEPER_SECRET_KEY": "env-secret",
          "CRYKEEPER_HUMAN_COOKIE_SECURE": "false",
          "CRYKEEPER_FOOTER_HTML": "from <strong>env</strong>",
          "CRYKEEPER_SKIP_ROUTES": "GET=^/assets/,POST=^/api/",
          "CRYKEEPER_BYPASS_USER_AGENTS": "^EnvBot$,^EnvCrawler/.*$",
          "CRYKEEPER_BYPASS_IPS": "198.51.100.7,2001:db8::1",
          "CRYKEEPER_ALLOW_KNOWN_SEARCH_ENGINES": "true",
          "CRYKEEPER_TRUSTED_PROXY_CIDRS": "203.0.113.0/24",
          "CRYKEEPER_RATE_LIMIT_BACKEND": "valkey",
          "CRYKEEPER_PATH_PREFIX": "/from-env",
        },
        clear=True,
      ):
        settings = load_settings()

    self.assertEqual("env-secret", settings.secret_key)
    self.assertEqual(321, settings.cookie_ttl_seconds)
    self.assertFalse(settings.cookie_secure)
    self.assertEqual("from <strong>env</strong>", settings.footer_html.resolve("de"))
    self.assertEqual(
      (("GET", "^/assets/"), ("POST", "^/api/")),
      tuple((rule.method, rule.pattern) for rule in settings.skip_routes),
    )
    self.assertEqual(
      ("^EnvBot$", "^EnvCrawler/.*$"),
      tuple(rule.pattern for rule in settings.bypass_user_agents),
    )
    self.assertEqual(
      ("198.51.100.7", "2001:db8::1"),
      tuple(rule.value for rule in settings.bypass_ips),
    )
    self.assertTrue(settings.allow_known_search_engines)
    self.assertEqual(("203.0.113.0/24",), settings.trusted_proxy_cidrs)
    self.assertEqual("valkey", settings.rate_limit_backend)
    self.assertEqual("/from-env", settings.path_prefix)

  def test_blank_environment_variables_fall_back_to_toml_settings(self):
    with tempfile.TemporaryDirectory() as temp_dir:
      config_path = self._write_config(
        temp_dir,
        """
                [crykeeper]
                secret_key = "file-secret"
                human_cookie_secure = true
                footer_html = "from file"
                skip_routes = ["^/from-file/"]
                bypass_user_agents = ["^FileBot$"]
                bypass_ips = ["2001:db8::/32"]
                allow_known_search_engines = true
                rate_limit_backend = "valkey"
                path_prefix = "/from-file"
                """,
      )

      with patch.dict(
        os.environ,
        {
          "CRYKEEPER_CONFIG_FILE": config_path,
          "CRYKEEPER_SECRET_KEY": "",
          "CRYKEEPER_HUMAN_COOKIE_SECURE": "   ",
          "CRYKEEPER_FOOTER_HTML": "",
          "CRYKEEPER_SKIP_ROUTES": "  ",
          "CRYKEEPER_BYPASS_USER_AGENTS": "",
          "CRYKEEPER_BYPASS_IPS": "  ",
          "CRYKEEPER_ALLOW_KNOWN_SEARCH_ENGINES": "",
          "CRYKEEPER_RATE_LIMIT_BACKEND": "",
          "CRYKEEPER_PATH_PREFIX": "",
        },
        clear=True,
      ):
        settings = load_settings()

    self.assertEqual("file-secret", settings.secret_key)
    self.assertTrue(settings.cookie_secure)
    self.assertEqual("from file", settings.footer_html.resolve("fr"))
    self.assertEqual(
      ((None, "^/from-file/"),),
      tuple((rule.method, rule.pattern) for rule in settings.skip_routes),
    )
    self.assertEqual(
      ("^FileBot$",), tuple(rule.pattern for rule in settings.bypass_user_agents)
    )
    self.assertEqual(
      ("2001:db8::/32",), tuple(rule.value for rule in settings.bypass_ips)
    )
    self.assertTrue(settings.allow_known_search_engines)
    self.assertEqual("valkey", settings.rate_limit_backend)
    self.assertEqual("/from-file", settings.path_prefix)

  def test_altcha_defaults_use_current_v3_widget_settings(self):
    with patch.dict(os.environ, {}, clear=True):
      settings = load_settings()

    self.assertEqual("", settings.altcha_script_url)
    self.assertEqual(
      "/crykeeper/static/vendor/altcha.min.js",
      settings.altcha_effective_script_url,
    )
    self.assertEqual("PBKDF2/SHA-256", settings.altcha_algorithm)

  def test_default_cookie_ttl_is_24_hours(self):
    with patch.dict(os.environ, {}, clear=True):
      settings = load_settings()

    self.assertEqual(24 * 60 * 60, settings.cookie_ttl_seconds)

  def test_unknown_toml_keys_fail_fast(self):
    with tempfile.TemporaryDirectory() as temp_dir:
      config_path = self._write_config(
        temp_dir,
        """
                [crykeeper]
                imaginary_setting = true
                """,
      )

      with patch.dict(os.environ, {"CRYKEEPER_CONFIG_FILE": config_path}, clear=True):
        with self.assertRaisesRegex(RuntimeError, "unknown keys"):
          load_settings()

  def test_website_overrides_apply_by_domain_and_beat_default_env_values(self):
    with tempfile.TemporaryDirectory() as temp_dir:
      config_path = self._write_config(
        temp_dir,
        """
                [crykeeper]
                secret_key = "file-secret"
                path_prefix = "/from-file"
                footer_html = { en = 'default footer', de = 'standardfuss' }
                skip_routes = ["^/shared/"]

                [[website]]
                domains = ["one.example.com", "TWO.example.com:443"]
                secret_key = "website-secret"
                human_cookie_secure = false
                footer_html = { de = '<a href="/legal">website footer</a>' }
                skip_routes = ["POST=^/site-api/", "GET=^/site-assets/"]
                path_prefix = "/site-check"
                cap_public_base_url = "https://site-cap.example.com/"
                cap_internal_base_url = ""
                """,
      )

      with patch.dict(
        os.environ,
        {
          "CRYKEEPER_CONFIG_FILE": config_path,
          "CRYKEEPER_SECRET_KEY": "env-secret",
          "CRYKEEPER_HUMAN_COOKIE_SECURE": "true",
          "CRYKEEPER_PATH_PREFIX": "/from-env",
        },
        clear=True,
      ):
        settings_bundle = load_settings_bundle()

    self.assertEqual("env-secret", settings_bundle.default_settings.secret_key)
    self.assertTrue(settings_bundle.default_settings.cookie_secure)
    self.assertEqual(
      "__Host-crykeeper_verified", settings_bundle.default_settings.cookie_name
    )
    self.assertEqual("/from-env", settings_bundle.default_settings.path_prefix)

    site_settings = settings_bundle.settings_for_host("one.example.com")
    port_settings = settings_bundle.settings_for_host("TWO.example.com:443")
    fallback_settings = settings_bundle.settings_for_host("missing.example.com")

    self.assertEqual("website-secret", site_settings.secret_key)
    self.assertFalse(site_settings.cookie_secure)
    self.assertEqual("crykeeper_verified", site_settings.cookie_name)
    self.assertEqual(
      '<a href="/legal">website footer</a>', site_settings.footer_html.resolve("de")
    )
    self.assertEqual("default footer", site_settings.footer_html.resolve("fr"))
    self.assertEqual(
      {
        "en": "default footer",
        "de": '<a href="/legal">website footer</a>',
      },
      site_settings.footer_html.by_locale,
    )
    self.assertEqual(
      (("POST", "^/site-api/"), ("GET", "^/site-assets/")),
      tuple((rule.method, rule.pattern) for rule in site_settings.skip_routes),
    )
    self.assertEqual("/site-check", site_settings.path_prefix)
    self.assertEqual(
      "https://site-cap.example.com", site_settings.cap_internal_base_url
    )
    self.assertEqual(site_settings, port_settings)
    self.assertEqual("standardfuss", fallback_settings.footer_html.resolve("de"))
    self.assertEqual(
      ((None, "^/shared/"),),
      tuple((rule.method, rule.pattern) for rule in fallback_settings.skip_routes),
    )
    self.assertEqual(settings_bundle.default_settings, fallback_settings)

  def test_invalid_skip_route_regex_fails_fast(self):
    with tempfile.TemporaryDirectory() as temp_dir:
      config_path = self._write_config(
        temp_dir,
        """
                [crykeeper]
                secret_key = "file-secret"
                skip_routes = ["GET=(["]
                """,
      )

      with patch.dict(os.environ, {"CRYKEEPER_CONFIG_FILE": config_path}, clear=True):
        with self.assertRaisesRegex(RuntimeError, "invalid regex"):
          load_settings()

  def test_invalid_bypass_user_agent_regex_fails_fast(self):
    with tempfile.TemporaryDirectory() as temp_dir:
      config_path = self._write_config(
        temp_dir,
        """
                [crykeeper]
                secret_key = "file-secret"
                bypass_user_agents = ["("]
                """,
      )

      with patch.dict(os.environ, {"CRYKEEPER_CONFIG_FILE": config_path}, clear=True):
        with self.assertRaisesRegex(RuntimeError, "invalid regex"):
          load_settings()

  def test_invalid_bypass_ip_fails_fast(self):
    with tempfile.TemporaryDirectory() as temp_dir:
      config_path = self._write_config(
        temp_dir,
        """
                [crykeeper]
                secret_key = "file-secret"
                bypass_ips = ["not-an-ip"]
                """,
      )

      with patch.dict(os.environ, {"CRYKEEPER_CONFIG_FILE": config_path}, clear=True):
        with self.assertRaisesRegex(RuntimeError, "invalid IP or CIDR"):
          load_settings()

  def test_website_overrides_reject_global_only_keys(self):
    with tempfile.TemporaryDirectory() as temp_dir:
      config_path = self._write_config(
        temp_dir,
        """
                [crykeeper]
                secret_key = "file-secret"

                [[website]]
                domains = ["one.example.com"]
                trusted_proxy_hops = 1
                """,
      )

      with patch.dict(os.environ, {"CRYKEEPER_CONFIG_FILE": config_path}, clear=True):
        with self.assertRaisesRegex(
          RuntimeError, "may not override trusted_proxy_hops"
        ):
          load_settings_bundle()

  def test_website_overrides_reject_global_rate_limit_valkey_url(self):
    with tempfile.TemporaryDirectory() as temp_dir:
      config_path = self._write_config(
        temp_dir,
        """
                [crykeeper]
                secret_key = "file-secret"

                [[website]]
                domains = ["one.example.com"]
                rate_limit_valkey_url = "redis://site-valkey:6379/1"
                """,
      )

      with patch.dict(os.environ, {"CRYKEEPER_CONFIG_FILE": config_path}, clear=True):
        with self.assertRaisesRegex(
          RuntimeError, "may not override rate_limit_valkey_url"
        ):
          load_settings_bundle()

  def test_duplicate_normalized_website_domains_fail_fast(self):
    with tempfile.TemporaryDirectory() as temp_dir:
      config_path = self._write_config(
        temp_dir,
        """
                [crykeeper]
                secret_key = "file-secret"

                [[website]]
                domains = ["ONE.example.com", "one.example.com:443"]
                """,
      )

      with patch.dict(os.environ, {"CRYKEEPER_CONFIG_FILE": config_path}, clear=True):
        with self.assertRaisesRegex(RuntimeError, "duplicate domain 'one.example.com'"):
          load_settings_bundle()

  def test_footer_html_supports_multiline_dotted_toml_keys(self):
    with tempfile.TemporaryDirectory() as temp_dir:
      config_path = self._write_config(
        temp_dir,
        """
                [crykeeper]
                secret_key = "file-secret"
                path_prefix = "/crykeeper"
                footer_html.en = "english footer"
                footer_html.de = "deutscher footer"

                [[website]]
                domains = ["one.example.com"]
                path_prefix = "/one-check"
                footer_html.de = "webseiten-footer"
                """,
      )

      with patch.dict(os.environ, {"CRYKEEPER_CONFIG_FILE": config_path}, clear=True):
        settings_bundle = load_settings_bundle()

    default_settings = settings_bundle.default_settings
    website_settings = settings_bundle.settings_for_host("one.example.com")

    self.assertEqual("deutscher footer", default_settings.footer_html.resolve("de"))
    self.assertEqual("english footer", default_settings.footer_html.resolve("fr"))
    self.assertEqual("webseiten-footer", website_settings.footer_html.resolve("de"))
    self.assertEqual("english footer", website_settings.footer_html.resolve("fr"))

  def test_footer_html_falls_back_from_regional_locale_to_base_language(self):
    with tempfile.TemporaryDirectory() as temp_dir:
      config_path = self._write_config(
        temp_dir,
        """
                [crykeeper]
                secret_key = "file-secret"
                footer_html.en = "english footer"
                footer_html.de = "deutscher footer"
                """,
      )

      with patch.dict(os.environ, {"CRYKEEPER_CONFIG_FILE": config_path}, clear=True):
        settings = load_settings()

    self.assertEqual("deutscher footer", settings.footer_html.resolve("de-AT"))
    self.assertEqual("english footer", settings.footer_html.resolve("fr-CA"))


if __name__ == "__main__":
  unittest.main()
