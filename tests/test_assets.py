import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app.assets import HASHED_ASSET_CACHE_MAX_AGE_SECONDS, load_asset_manifest
from app.observability import observability as observability_blueprint
from app.routes import crykeeper

from app import create_app


class CryKeeperAssetManifestTests(unittest.TestCase):
  def setUp(self):
    load_asset_manifest.cache_clear()

  def tearDown(self):
    load_asset_manifest.cache_clear()

  def _create_app(self, **env_overrides):
    env = {
      "CRYKEEPER_SECRET_KEY": "test-secret",
      "CRYKEEPER_VERIFICATION_MODE": "dummy",
      "CRYKEEPER_HUMAN_COOKIE_SECURE": "false",
      "CRYKEEPER_TRUSTED_PROXY_HOPS": "0",
    }
    env.update(env_overrides)

    with patch.dict(os.environ, env, clear=True):
      return create_app()

  def _write_config(self, directory: str, contents: str) -> str:
    config_path = Path(directory) / "config.toml"
    config_path.write_text(contents, encoding="utf-8")
    return str(config_path)

  def test_challenge_and_dashboard_resolve_hashed_assets_from_manifest(self):
    manifest = {
      "ui.css": "ui-a1b2c3d4e5f6.css",
      "challenge-common.js": "challenge-common-111111111111.js",
      "challenge-dummy.js": "challenge-dummy-222222222222.js",
      "dashboard.css": "dashboard-333333333333.css",
      "dashboard.js": "dashboard-444444444444.js",
      "verify-redirect.js": "verify-redirect-555555555555.js",
    }

    with tempfile.TemporaryDirectory() as tmpdir:
      manifest_path = Path(tmpdir) / "asset-manifest.json"
      manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

      with patch("app.assets._manifest_path", return_value=manifest_path):
        load_asset_manifest.cache_clear()
        app = self._create_app()
        client = app.test_client()

        challenge_response = client.get(
          "/crykeeper/challenge",
          base_url="http://localhost",
          query_string={"return": "/ok"},
        )
        verify_response = client.post(
          "/crykeeper/verify",
          base_url="http://localhost",
          data={"return": "/ok"},
        )
        dashboard_response = client.get(
          "/_crykeeper/dashboard",
          base_url="http://localhost",
        )

    try:
      self.assertEqual(200, challenge_response.status_code)
      self.assertEqual(200, verify_response.status_code)
      self.assertEqual(200, dashboard_response.status_code)

      challenge_body = challenge_response.get_data(as_text=True)
      verify_body = verify_response.get_data(as_text=True)
      dashboard_body = dashboard_response.get_data(as_text=True)

      self.assertIn("/crykeeper/static/ui-a1b2c3d4e5f6.css", challenge_body)
      self.assertIn(
        "/crykeeper/static/challenge-common-111111111111.js", challenge_body
      )
      self.assertIn("/crykeeper/static/challenge-dummy-222222222222.js", challenge_body)
      self.assertIn("/crykeeper/static/ui-a1b2c3d4e5f6.css", verify_body)
      self.assertIn("/crykeeper/static/verify-redirect-555555555555.js", verify_body)
      self.assertIn("/_crykeeper/static/ui-a1b2c3d4e5f6.css", dashboard_body)
      self.assertIn("/_crykeeper/static/dashboard-333333333333.css", dashboard_body)
      self.assertIn("/_crykeeper/static/dashboard-444444444444.js", dashboard_body)
    finally:
      challenge_response.close()
      verify_response.close()
      dashboard_response.close()

  def test_hashed_static_assets_get_14_day_cache_headers(self):
    manifest = {
      "ui.css": "ui-a1b2c3d4e5f6.css",
      "challenge-common.js": "challenge-common-111111111111.js",
      "dashboard.css": "dashboard-333333333333.css",
    }
    expected_cache_control = (
      f"public, max-age={HASHED_ASSET_CACHE_MAX_AGE_SECONDS}, immutable"
    )

    with tempfile.TemporaryDirectory() as tmpdir:
      manifest_path = Path(tmpdir) / "asset-manifest.json"
      manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
      static_root = Path(tmpdir) / "static"
      static_root.mkdir()
      (static_root / manifest["challenge-common.js"]).write_text(
        "console.log('challenge');", encoding="utf-8"
      )
      (static_root / manifest["dashboard.css"]).write_text(
        ".dashboard-shell{display:block}", encoding="utf-8"
      )
      (static_root / "ui.css").write_text("body{color:black}", encoding="utf-8")

      with patch("app.assets._manifest_path", return_value=manifest_path):
        with patch.object(crykeeper, "_static_folder", str(static_root)):
          with patch.object(
            observability_blueprint, "_static_folder", str(static_root)
          ):
            load_asset_manifest.cache_clear()
            app = self._create_app()
            client = app.test_client()
            challenge_asset_response = client.get(
              f"/crykeeper/static/{manifest['challenge-common.js']}",
              base_url="http://localhost",
            )
            dashboard_asset_response = client.get(
              f"/_crykeeper/static/{manifest['dashboard.css']}",
              base_url="http://localhost",
            )
            unhashed_asset_response = client.get(
              "/crykeeper/static/ui.css",
              base_url="http://localhost",
            )

    try:
      self.assertEqual(200, challenge_asset_response.status_code)
      self.assertEqual(200, dashboard_asset_response.status_code)
      self.assertEqual(200, unhashed_asset_response.status_code)
      self.assertEqual(
        expected_cache_control,
        challenge_asset_response.headers.get("Cache-Control"),
      )
      self.assertEqual(
        expected_cache_control,
        dashboard_asset_response.headers.get("Cache-Control"),
      )
      self.assertNotIn(
        str(HASHED_ASSET_CACHE_MAX_AGE_SECONDS),
        unhashed_asset_response.headers.get("Cache-Control", ""),
      )
    finally:
      challenge_asset_response.close()
      dashboard_asset_response.close()
      unhashed_asset_response.close()

  def test_hashed_static_assets_get_14_day_cache_headers_for_website_prefix(self):
    manifest = {
      "challenge-common.js": "challenge-common-111111111111.js",
    }
    expected_cache_control = (
      f"public, max-age={HASHED_ASSET_CACHE_MAX_AGE_SECONDS}, immutable"
    )

    with tempfile.TemporaryDirectory() as tmpdir:
      config_path = self._write_config(
        tmpdir,
        """
[crykeeper]
secret_key = "default-secret"
verification_mode = "dummy"
human_cookie_secure = false
path_prefix = "/crykeeper"

[[website]]
domains = ["one.example.com"]
path_prefix = "/one-check"
""".strip(),
      )
      manifest_path = Path(tmpdir) / "asset-manifest.json"
      manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
      static_root = Path(tmpdir) / "static"
      static_root.mkdir()
      (static_root / manifest["challenge-common.js"]).write_text(
        "console.log('challenge');", encoding="utf-8"
      )

      with patch("app.assets._manifest_path", return_value=manifest_path):
        with patch.object(crykeeper, "_static_folder", str(static_root)):
          load_asset_manifest.cache_clear()
          app = self._create_app(CRYKEEPER_CONFIG_FILE=config_path)
          response = app.test_client().get(
            f"/one-check/static/{manifest['challenge-common.js']}",
            base_url="https://one.example.com",
          )

    try:
      self.assertEqual(200, response.status_code)
      self.assertEqual(
        expected_cache_control,
        response.headers.get("Cache-Control"),
      )
    finally:
      response.close()
