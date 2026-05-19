import os
import tempfile
import textwrap
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from altcha import Challenge as AltchaChallenge
from altcha import Payload as AltchaPayload
from altcha import solve_challenge as solve_altcha_challenge
from app.captcha.base import VerificationResult
from app.captcha.cap import CapVerificationResult

from app import create_app


class GatekeeperHardeningTests(unittest.TestCase):
  def _write_config(self, directory: str, contents: str) -> str:
    config_path = Path(directory) / "config.toml"
    config_path.write_text(textwrap.dedent(contents), encoding="utf-8")
    return str(config_path)

  def _create_app(self, **env_overrides):
    env = {
      "GATEKEEPER_SECRET_KEY": "test-secret",
      "GATEKEEPER_VERIFICATION_MODE": "dummy",
      "GATEKEEPER_HUMAN_COOKIE_SECURE": "false",
      "GATEKEEPER_TRUSTED_PROXY_HOPS": "0",
    }
    env.update(env_overrides)

    with patch.dict(os.environ, env, clear=True):
      return create_app()

  def test_cap_mode_requires_secure_cookie_without_local_override(self):
    with self.assertRaisesRegex(RuntimeError, "ALLOW_INSECURE_LOCAL_CAP"):
      self._create_app(
        GATEKEEPER_VERIFICATION_MODE="cap",
        GATEKEEPER_HUMAN_COOKIE_SECURE="false",
        GATEKEEPER_CAP_PUBLIC_BASE_URL="http://localhost:3000",
        GATEKEEPER_CAP_SITE_KEY="site-key",
        GATEKEEPER_CAP_SECRET_KEY="secret-key",
      )

  def test_create_app_rejects_default_secret_key(self):
    with patch.dict(
      os.environ,
      {
        "GATEKEEPER_SECRET_KEY": "change-me-in-production",
        "GATEKEEPER_VERIFICATION_MODE": "dummy",
      },
      clear=True,
    ):
      with self.assertRaisesRegex(RuntimeError, "development default"):
        create_app()

  def test_create_app_rejects_trusted_proxy_hops_without_cidrs(self):
    with patch.dict(
      os.environ,
      {
        "GATEKEEPER_SECRET_KEY": "test-secret",
        "GATEKEEPER_VERIFICATION_MODE": "dummy",
        "GATEKEEPER_TRUSTED_PROXY_HOPS": "1",
      },
      clear=True,
    ):
      with self.assertRaisesRegex(RuntimeError, "TRUSTED_PROXY_CIDRS"):
        create_app()

  def test_cap_mode_allows_explicit_local_http_override(self):
    app = self._create_app(
      GATEKEEPER_VERIFICATION_MODE="cap",
      GATEKEEPER_HUMAN_COOKIE_SECURE="false",
      GATEKEEPER_ALLOW_INSECURE_LOCAL_CAP="true",
      GATEKEEPER_CAP_PUBLIC_BASE_URL="http://localhost:3000",
      GATEKEEPER_CAP_ASSET_BASE_URL="http://localhost:3000",
      GATEKEEPER_CAP_SITE_KEY="site-key",
      GATEKEEPER_CAP_SECRET_KEY="secret-key",
    )

    local_response = app.test_client().get(
      "/gatekeeper/challenge",
      base_url="http://localhost",
      query_string={"return": "/ok"},
    )
    non_local_response = app.test_client().get(
      "/gatekeeper/challenge",
      base_url="http://example.com",
      query_string={"return": "/ok"},
    )

    self.assertEqual(200, local_response.status_code)
    self.assertEqual(400, non_local_response.status_code)

  def test_ip_binding_uses_trusted_proxy_hop(self):
    app = self._create_app(
      GATEKEEPER_HUMAN_COOKIE_BINDING="ip-user-agent",
      GATEKEEPER_TRUSTED_PROXY_HOPS="1",
      GATEKEEPER_TRUSTED_PROXY_CIDRS="10.0.0.0/8",
    )
    client = app.test_client()

    client.post(
      "/gatekeeper/verify",
      base_url="http://localhost",
      data={"return": "/ok"},
      headers={
        "User-Agent": "UA",
        "X-Forwarded-For": "1.1.1.1, 2.2.2.2",
      },
      environ_overrides={"REMOTE_ADDR": "10.0.0.5"},
    )

    same_trusted_hop = client.get(
      "/gatekeeper/check",
      base_url="http://localhost",
      headers={
        "X-Original-URI": "/ok",
        "User-Agent": "UA",
        "X-Forwarded-For": "9.9.9.9, 2.2.2.2",
      },
      environ_overrides={"REMOTE_ADDR": "10.0.0.5"},
    )
    different_trusted_hop = client.get(
      "/gatekeeper/check",
      base_url="http://localhost",
      headers={
        "X-Original-URI": "/ok",
        "User-Agent": "UA",
        "X-Forwarded-For": "9.9.9.9, 8.8.8.8",
      },
      environ_overrides={"REMOTE_ADDR": "10.0.0.5"},
    )

    self.assertEqual(204, same_trusted_hop.status_code)
    self.assertEqual(401, different_trusted_hop.status_code)

  def test_untrusted_proxy_headers_are_ignored(self):
    app = self._create_app(
      GATEKEEPER_HUMAN_COOKIE_BINDING="ip-user-agent",
      GATEKEEPER_TRUSTED_PROXY_HOPS="1",
      GATEKEEPER_TRUSTED_PROXY_CIDRS="10.0.0.0/8",
    )
    client = app.test_client()

    client.post(
      "/gatekeeper/verify",
      base_url="http://localhost",
      data={"return": "/ok"},
      headers={
        "User-Agent": "UA",
        "X-Forwarded-For": "1.1.1.1, 2.2.2.2",
      },
      environ_overrides={"REMOTE_ADDR": "203.0.113.5"},
    )

    replay = client.get(
      "/gatekeeper/check",
      base_url="http://localhost",
      headers={
        "X-Original-URI": "/ok",
        "User-Agent": "UA",
        "X-Forwarded-For": "9.9.9.9, 8.8.8.8",
      },
      environ_overrides={"REMOTE_ADDR": "203.0.113.5"},
    )

    self.assertEqual(204, replay.status_code)

  def test_non_local_verification_requires_secure_cookie_policy(self):
    app = self._create_app()
    response = app.test_client().get(
      "/gatekeeper/challenge",
      base_url="http://example.com",
      query_string={"return": "/ok"},
    )

    self.assertEqual(400, response.status_code)
    self.assertIn("HTTPS", response.get_data(as_text=True))

  def test_secure_cookie_defaults_to_host_prefix(self):
    app = self._create_app(GATEKEEPER_HUMAN_COOKIE_SECURE="true")
    response = app.test_client().post(
      "/gatekeeper/verify",
      base_url="https://example.com",
      data={"return": "/ok"},
      headers={"User-Agent": "UA"},
    )

    set_cookie = response.headers["Set-Cookie"]
    self.assertTrue(set_cookie.startswith("__Host-gatekeeper_verified="))
    self.assertIn("Secure", set_cookie)

  def test_skip_routes_bypass_auth_for_matching_method_and_path(self):
    app = self._create_app(GATEKEEPER_SKIP_ROUTES="^/public/,POST=^/api/")
    client = app.test_client()

    public_response = client.get(
      "/gatekeeper/check",
      base_url="http://localhost",
      headers={
        "X-Original-Method": "GET",
        "X-Original-URI": "/public/logo.svg?cache=1",
      },
    )
    api_post_response = client.get(
      "/gatekeeper/check",
      base_url="http://localhost",
      headers={
        "X-Original-Method": "POST",
        "X-Original-URI": "/api/items",
      },
    )
    api_get_response = client.get(
      "/gatekeeper/check",
      base_url="http://localhost",
      headers={
        "X-Original-Method": "GET",
        "X-Original-URI": "/api/items",
      },
    )

    self.assertEqual(204, public_response.status_code)
    self.assertEqual(204, api_post_response.status_code)
    self.assertEqual(401, api_get_response.status_code)

  def test_domain_specific_skip_routes_override_shared_defaults(self):
    with tempfile.TemporaryDirectory() as temp_dir:
      config_path = self._write_config(
        temp_dir,
        """
                [gatekeeper]
                secret_key = "default-secret"
                human_cookie_secure = false
                skip_routes = ["^/shared-public/"]
                path_prefix = "/gatekeeper"

                [[website]]
                domains = ["one.example.com"]
                human_cookie_secure = true
                skip_routes = ["POST=^/api/"]
                path_prefix = "/one-check"
                """,
      )

      with patch.dict(
        os.environ,
        {
          "GATEKEEPER_CONFIG_FILE": config_path,
          "GATEKEEPER_VERIFICATION_MODE": "dummy",
          "GATEKEEPER_TRUSTED_PROXY_HOPS": "0",
        },
        clear=True,
      ):
        app = create_app()

    client = app.test_client()
    shared_default_route = client.get(
      "/gatekeeper/check",
      base_url="http://localhost",
      headers={
        "X-Original-Method": "GET",
        "X-Original-URI": "/shared-public/index.html",
      },
    )
    website_post_route = client.get(
      "/one-check/check",
      base_url="https://one.example.com",
      headers={
        "X-Original-Method": "POST",
        "X-Original-URI": "/api/items",
      },
    )
    website_inherited_default = client.get(
      "/one-check/check",
      base_url="https://one.example.com",
      headers={
        "X-Original-Method": "GET",
        "X-Original-URI": "/shared-public/index.html",
      },
    )

    self.assertEqual(204, shared_default_route.status_code)
    self.assertEqual(204, website_post_route.status_code)
    self.assertEqual(401, website_inherited_default.status_code)

  def test_challenge_rate_limit_returns_retry_after(self):
    app = self._create_app(
      GATEKEEPER_CHALLENGE_RATE_LIMIT_REQUESTS="2",
      GATEKEEPER_CHALLENGE_RATE_LIMIT_WINDOW_SECONDS="60",
      GATEKEEPER_CHALLENGE_RATE_LIMIT_BLOCK_SECONDS="30",
    )
    client = app.test_client()

    for _ in range(2):
      response = client.get(
        "/gatekeeper/challenge",
        base_url="http://localhost",
        query_string={"return": "/ok"},
      )
      self.assertEqual(200, response.status_code)

    limited = client.get(
      "/gatekeeper/challenge",
      base_url="http://localhost",
      query_string={"return": "/ok"},
    )

    self.assertEqual(429, limited.status_code)
    self.assertEqual("30", limited.headers["Retry-After"])

  def test_verify_rate_limit_returns_retry_after(self):
    app = self._create_app(
      GATEKEEPER_VERIFY_RATE_LIMIT_REQUESTS="1",
      GATEKEEPER_VERIFY_RATE_LIMIT_WINDOW_SECONDS="60",
      GATEKEEPER_VERIFY_RATE_LIMIT_BLOCK_SECONDS="45",
    )
    client = app.test_client()

    first = client.post(
      "/gatekeeper/verify",
      base_url="http://localhost",
      data={"return": "/ok"},
      headers={"User-Agent": "UA"},
    )
    limited = client.post(
      "/gatekeeper/verify",
      base_url="http://localhost",
      data={"return": "/ok"},
      headers={"User-Agent": "UA"},
    )

    self.assertEqual(302, first.status_code)
    self.assertEqual(429, limited.status_code)
    self.assertEqual("45", limited.headers["Retry-After"])

  def test_clear_endpoint_deletes_cookie_and_redirects(self):
    app = self._create_app()
    client = app.test_client()

    client.post(
      "/gatekeeper/verify",
      base_url="http://localhost",
      data={"return": "/ok"},
      headers={"User-Agent": "UA"},
    )
    before_clear = client.get(
      "/gatekeeper/check",
      base_url="http://localhost",
      headers={"X-Original-URI": "/ok", "User-Agent": "UA"},
    )
    cleared = client.get(
      "/gatekeeper/clear",
      base_url="http://localhost",
      query_string={"return": "/signed-out"},
    )
    after_clear = client.get(
      "/gatekeeper/check",
      base_url="http://localhost",
      headers={"X-Original-URI": "/ok", "User-Agent": "UA"},
    )

    self.assertEqual(204, before_clear.status_code)
    self.assertEqual(302, cleared.status_code)
    self.assertEqual("/signed-out", cleared.headers["Location"])
    self.assertIn("gatekeeper_verified=;", cleared.headers["Set-Cookie"])
    self.assertIn("Max-Age=0", cleared.headers["Set-Cookie"])
    self.assertEqual(401, after_clear.status_code)

  def test_clear_endpoint_replaces_blocked_gatekeeper_return_path_with_root(self):
    app = self._create_app()
    response = app.test_client().get(
      "/gatekeeper/clear",
      base_url="http://localhost",
      query_string={"return": "/gatekeeper/challenge?return=/ok"},
    )

    self.assertEqual(302, response.status_code)
    self.assertEqual("/", response.headers["Location"])

  def test_clear_endpoint_replaces_dot_segment_gatekeeper_return_path_with_root(self):
    app = self._create_app()
    response = app.test_client().get(
      "/gatekeeper/clear",
      base_url="http://localhost",
      query_string={"return": "/safe/../gatekeeper/challenge?return=/ok"},
    )

    self.assertEqual(302, response.status_code)
    self.assertEqual("/", response.headers["Location"])

  def test_auth_redirect_replaces_blocked_gatekeeper_return_path_with_root(self):
    app = self._create_app()
    response = app.test_client().get(
      "/gatekeeper/check",
      base_url="http://localhost",
      headers={"X-Original-URI": "/gatekeeper/challenge?return=/ok"},
    )

    self.assertEqual(401, response.status_code)
    self.assertEqual(
      "/gatekeeper/challenge?return=%2F", response.headers["X-Auth-Redirect"]
    )

  def test_auth_redirect_replaces_dot_segment_gatekeeper_return_path_with_root(self):
    app = self._create_app()
    response = app.test_client().get(
      "/gatekeeper/check",
      base_url="http://localhost",
      headers={"X-Original-URI": "/safe/%2E%2E/gatekeeper/challenge?return=/ok"},
    )

    self.assertEqual(401, response.status_code)
    self.assertEqual(
      "/gatekeeper/challenge?return=%2F", response.headers["X-Auth-Redirect"]
    )

  def test_verify_replaces_percent_encoded_gatekeeper_return_path_with_root(self):
    app = self._create_app()
    response = app.test_client().post(
      "/gatekeeper/verify",
      base_url="http://localhost",
      data={"return": "/gatekeeper%2Fchallenge?return=/ok"},
      headers={"User-Agent": "UA"},
    )

    self.assertEqual(302, response.status_code)
    self.assertEqual("/", response.headers["Location"])

  def test_cap_verify_requires_token(self):
    app = self._create_app(
      GATEKEEPER_VERIFICATION_MODE="cap",
      GATEKEEPER_HUMAN_COOKIE_SECURE="true",
      GATEKEEPER_CAP_PUBLIC_BASE_URL="https://cap.example.com",
      GATEKEEPER_CAP_SITE_KEY="site-key",
      GATEKEEPER_CAP_SECRET_KEY="secret-key",
    )
    response = app.test_client().post(
      "/gatekeeper/verify",
      base_url="https://example.com",
      data={"return": "/ok"},
    )

    self.assertEqual(400, response.status_code)
    self.assertNotIn("Set-Cookie", response.headers)

  @patch("app.routes.verify_cap_token")
  def test_cap_verify_success_sets_cookie_and_redirects(self, verify_cap_token):
    verify_cap_token.return_value = CapVerificationResult(
      success=True,
      retryable=False,
      message=None,
      payload={"success": True},
    )

    app = self._create_app(
      GATEKEEPER_VERIFICATION_MODE="cap",
      GATEKEEPER_HUMAN_COOKIE_SECURE="true",
      GATEKEEPER_CAP_PUBLIC_BASE_URL="https://cap.example.com",
      GATEKEEPER_CAP_SITE_KEY="site-key",
      GATEKEEPER_CAP_SECRET_KEY="secret-key",
    )
    response = app.test_client().post(
      "/gatekeeper/verify",
      base_url="https://example.com",
      data={"return": "/ok", "cap-token": "good-token"},
      headers={"User-Agent": "UA"},
    )

    self.assertEqual(302, response.status_code)
    self.assertEqual("/ok", response.headers["Location"])
    self.assertIn("Set-Cookie", response.headers)
    verify_cap_token.assert_called_once_with(
      "https://cap.example.com/site-key/siteverify",
      "secret-key",
      "good-token",
      5,
    )

  @patch("app.routes.verify_cap_token")
  def test_cap_verify_retryable_failure_returns_bad_gateway(self, verify_cap_token):
    verify_cap_token.return_value = CapVerificationResult(
      success=False,
      retryable=True,
      message="temporarily unavailable",
      payload=None,
    )

    app = self._create_app(
      GATEKEEPER_VERIFICATION_MODE="cap",
      GATEKEEPER_HUMAN_COOKIE_SECURE="true",
      GATEKEEPER_CAP_PUBLIC_BASE_URL="https://cap.example.com",
      GATEKEEPER_CAP_SITE_KEY="site-key",
      GATEKEEPER_CAP_SECRET_KEY="secret-key",
    )
    response = app.test_client().post(
      "/gatekeeper/verify",
      base_url="https://example.com",
      data={"return": "/ok", "cap-token": "retry-token"},
    )

    self.assertEqual(502, response.status_code)
    self.assertNotIn("Set-Cookie", response.headers)
    verify_cap_token.assert_called_once_with(
      "https://cap.example.com/site-key/siteverify",
      "secret-key",
      "retry-token",
      5,
    )

  def test_challenge_page_uses_external_script_with_csp(self):
    app = self._create_app(
      GATEKEEPER_VERIFICATION_MODE="cap",
      GATEKEEPER_HUMAN_COOKIE_SECURE="true",
      GATEKEEPER_CAP_PUBLIC_BASE_URL="https://cap.example.com",
      GATEKEEPER_CAP_ASSET_BASE_URL="https://cap.example.com",
      GATEKEEPER_CAP_SITE_KEY="site-key",
      GATEKEEPER_CAP_SECRET_KEY="secret-key",
    )
    response = app.test_client().get(
      "/gatekeeper/challenge",
      base_url="https://example.com",
      query_string={"return": "/ok"},
    )

    body = response.get_data(as_text=True)
    csp = response.headers["Content-Security-Policy"]
    self.assertIn(
      "script-src 'self' 'unsafe-eval' 'wasm-unsafe-eval' https://cap.example.com", csp
    )
    self.assertIn("script-src-elem 'self' https://cap.example.com 'unsafe-inline'", csp)
    self.assertIn("/gatekeeper/static/challenge-common.js", body)
    self.assertIn("/gatekeeper/static/challenge-cap.js", body)
    self.assertNotIn("/gatekeeper/static/challenge-dummy.js", body)
    self.assertIn("https://cap.example.com/assets/widget.js", body)
    self.assertNotIn("<script>", body)
    self.assertNotIn('type="application/json"', body)

  def test_dummy_challenge_page_uses_dummy_script_only(self):
    app = self._create_app()
    response = app.test_client().get(
      "/gatekeeper/challenge",
      base_url="http://localhost",
      query_string={"return": "/ok"},
    )

    body = response.get_data(as_text=True)
    self.assertIn("/gatekeeper/static/challenge-common.js", body)
    self.assertIn("/gatekeeper/static/challenge-dummy.js", body)
    self.assertNotIn("/gatekeeper/static/challenge-cap.js", body)

  def test_hcaptcha_challenge_page_uses_hcaptcha_scripts_with_csp(self):
    app = self._create_app(
      GATEKEEPER_VERIFICATION_MODE="hcaptcha",
      GATEKEEPER_HUMAN_COOKIE_SECURE="true",
      GATEKEEPER_HCAPTCHA_SITE_KEY="site-key",
      GATEKEEPER_HCAPTCHA_SECRET_KEY="secret-key",
    )
    response = app.test_client().get(
      "/gatekeeper/challenge",
      base_url="https://example.com",
      query_string={"return": "/ok"},
    )

    body = response.get_data(as_text=True)
    csp = response.headers["Content-Security-Policy"]
    self.assertIn("/gatekeeper/static/challenge-common.js", body)
    self.assertIn("/gatekeeper/static/challenge-hcaptcha.js", body)
    self.assertIn("https://js.hcaptcha.com/1/api.js?render=explicit", body)
    self.assertNotIn("&#34;invisible&#34;: true", body)
    self.assertNotIn('id="action-button"', body)
    self.assertIn("frame-src https://hcaptcha.com https://*.hcaptcha.com", csp)
    self.assertIn("connect-src 'self' https://hcaptcha.com https://*.hcaptcha.com", csp)

  def test_altcha_challenge_page_uses_altcha_scripts_and_endpoint(self):
    app = self._create_app(
      GATEKEEPER_VERIFICATION_MODE="altcha",
      GATEKEEPER_HUMAN_COOKIE_SECURE="true",
      GATEKEEPER_ALTCHA_HMAC_SECRET="altcha-secret",
    )
    response = app.test_client().get(
      "/gatekeeper/challenge",
      base_url="https://example.com",
      query_string={"return": "/ok"},
    )

    body = response.get_data(as_text=True)
    csp = response.headers["Content-Security-Policy"]
    self.assertIn("/gatekeeper/static/challenge-common.js", body)
    self.assertIn("/gatekeeper/static/challenge-altcha.js", body)
    self.assertIn("/gatekeeper/static/vendor/altcha.min.js", body)
    self.assertIn("/gatekeeper/altcha/challenge", body)
    self.assertIn('type="module"', body)
    self.assertIn("worker-src 'self' blob:", csp)

  @patch("app.routes.verify_hcaptcha_request")
  def test_hcaptcha_verify_success_sets_cookie_and_redirects(
    self, verify_hcaptcha_request
  ):
    verify_hcaptcha_request.return_value = VerificationResult(
      success=True,
      retryable=False,
    )

    app = self._create_app(
      GATEKEEPER_VERIFICATION_MODE="hcaptcha",
      GATEKEEPER_HUMAN_COOKIE_SECURE="true",
      GATEKEEPER_HCAPTCHA_SITE_KEY="site-key",
      GATEKEEPER_HCAPTCHA_SECRET_KEY="secret-key",
    )
    response = app.test_client().post(
      "/gatekeeper/verify",
      base_url="https://example.com",
      data={"return": "/ok", "h-captcha-response": "good-token"},
      headers={"User-Agent": "UA"},
    )

    self.assertEqual(302, response.status_code)
    self.assertEqual("/ok", response.headers["Location"])
    verify_hcaptcha_request.assert_called_once()

  @patch("app.routes.verify_hcaptcha_request")
  def test_hcaptcha_verify_retryable_failure_returns_bad_gateway(
    self, verify_hcaptcha_request
  ):
    verify_hcaptcha_request.return_value = VerificationResult(
      success=False,
      retryable=True,
      message="temporarily unavailable",
      payload=None,
    )

    app = self._create_app(
      GATEKEEPER_VERIFICATION_MODE="hcaptcha",
      GATEKEEPER_HUMAN_COOKIE_SECURE="true",
      GATEKEEPER_HCAPTCHA_SITE_KEY="site-key",
      GATEKEEPER_HCAPTCHA_SECRET_KEY="secret-key",
    )
    response = app.test_client().post(
      "/gatekeeper/verify",
      base_url="https://example.com",
      data={"return": "/ok", "h-captcha-response": "retry-token"},
    )

    self.assertEqual(502, response.status_code)
    self.assertNotIn("Set-Cookie", response.headers)
    verify_hcaptcha_request.assert_called_once()

  @patch("app.routes.verify_hcaptcha_request")
  def test_hcaptcha_verify_failure_returns_forbidden(self, verify_hcaptcha_request):
    verify_hcaptcha_request.return_value = VerificationResult(
      success=False,
      retryable=False,
      error_key="error_failed",
      status_code=403,
      payload={"success": False},
    )

    app = self._create_app(
      GATEKEEPER_VERIFICATION_MODE="hcaptcha",
      GATEKEEPER_HUMAN_COOKIE_SECURE="true",
      GATEKEEPER_HCAPTCHA_SITE_KEY="site-key",
      GATEKEEPER_HCAPTCHA_SECRET_KEY="secret-key",
    )
    response = app.test_client().post(
      "/gatekeeper/verify",
      base_url="https://example.com",
      data={"return": "/ok", "h-captcha-response": "bad-token"},
    )

    self.assertEqual(403, response.status_code)
    self.assertNotIn("Set-Cookie", response.headers)
    verify_hcaptcha_request.assert_called_once()

  @patch("app.routes.create_altcha_challenge")
  def test_altcha_challenge_endpoint_returns_json(self, create_altcha_challenge):
    create_altcha_challenge.return_value = {"challenge": "payload"}

    app = self._create_app(
      GATEKEEPER_VERIFICATION_MODE="altcha",
      GATEKEEPER_HUMAN_COOKIE_SECURE="true",
      GATEKEEPER_ALTCHA_HMAC_SECRET="altcha-secret",
    )
    response = app.test_client().get(
      "/gatekeeper/altcha/challenge",
      base_url="https://example.com",
      query_string={"return": "/ok"},
    )

    self.assertEqual(200, response.status_code)
    self.assertEqual({"challenge": "payload"}, response.get_json())

  def test_altcha_verify_success_sets_cookie_and_redirects(self):
    app = self._create_app(
      GATEKEEPER_VERIFICATION_MODE="altcha",
      GATEKEEPER_HUMAN_COOKIE_SECURE="true",
      GATEKEEPER_ALTCHA_HMAC_SECRET="altcha-secret",
      GATEKEEPER_ALTCHA_CHALLENGE_COST="10",
    )
    client = app.test_client()

    challenge_response = client.get(
      "/gatekeeper/altcha/challenge",
      base_url="https://example.com",
      query_string={"return": "/ok"},
    )
    challenge_data = challenge_response.get_json()
    self.assertIsNotNone(challenge_data)

    challenge = AltchaChallenge.from_dict(challenge_data)
    solution = solve_altcha_challenge(challenge)
    self.assertIsNotNone(solution)
    if solution is None:
      return

    payload = AltchaPayload(challenge, solution).to_base64()

    response = client.post(
      "/gatekeeper/verify",
      base_url="https://example.com",
      data={"return": "/ok", "altcha": payload},
      headers={"User-Agent": "UA"},
    )

    self.assertEqual(302, response.status_code)
    self.assertEqual("/ok", response.headers["Location"])

  def test_altcha_bundled_widget_is_served_locally(self):
    app = self._create_app(
      GATEKEEPER_VERIFICATION_MODE="altcha",
      GATEKEEPER_HUMAN_COOKIE_SECURE="true",
      GATEKEEPER_ALTCHA_HMAC_SECRET="altcha-secret",
    )
    response = app.test_client().get(
      "/gatekeeper/static/vendor/altcha.min.js",
      base_url="https://example.com",
    )
    try:
      self.assertEqual(200, response.status_code)
      self.assertIn("javascript", response.headers["Content-Type"])
      self.assertIn("Worker", response.get_data(as_text=True))
    finally:
      response.close()

  def test_challenge_page_renders_configured_footer_html(self):
    app = self._create_app(GATEKEEPER_FOOTER_HTML="powered by <strong>cryMG</strong>")
    response = app.test_client().get(
      "/gatekeeper/challenge",
      base_url="http://localhost",
      query_string={"return": "/ok"},
    )

    body = response.get_data(as_text=True)
    self.assertIn("powered by <strong>cryMG</strong>", body)
    self.assertNotIn("powered by &lt;strong&gt;cryMG&lt;/strong&gt;", body)

  def test_challenge_page_localizes_footer_html_with_english_fallback(self):
    with tempfile.TemporaryDirectory() as temp_dir:
      config_path = self._write_config(
        temp_dir,
        """
                [gatekeeper]
                secret_key = "default-secret"
                human_cookie_secure = false
                footer_html = { en = 'default <strong>footer</strong>', de = 'standard <strong>fuss</strong>' }
                path_prefix = "/gatekeeper"
                """,
      )

      with patch.dict(
        os.environ,
        {
          "GATEKEEPER_CONFIG_FILE": config_path,
          "GATEKEEPER_VERIFICATION_MODE": "dummy",
          "GATEKEEPER_TRUSTED_PROXY_HOPS": "0",
        },
        clear=True,
      ):
        app = create_app()

    client = app.test_client()
    german_response = client.get(
      "/gatekeeper/challenge",
      base_url="http://localhost",
      headers={"Accept-Language": "de"},
      query_string={"return": "/ok"},
    )
    french_response = client.get(
      "/gatekeeper/challenge",
      base_url="http://localhost",
      headers={"Accept-Language": "fr"},
      query_string={"return": "/ok"},
    )

    german_body = german_response.get_data(as_text=True)
    french_body = french_response.get_data(as_text=True)

    self.assertIn("standard <strong>fuss</strong>", german_body)
    self.assertIn("default <strong>footer</strong>", french_body)
    self.assertNotIn("standard <strong>fuss</strong>", french_body)

  def test_domain_specific_footer_html_overrides_default(self):
    with tempfile.TemporaryDirectory() as temp_dir:
      config_path = self._write_config(
        temp_dir,
        """
                [gatekeeper]
                secret_key = "default-secret"
                human_cookie_secure = false
                footer_html = { en = 'default <strong>footer</strong>', de = 'standard <strong>fuss</strong>' }
                path_prefix = "/gatekeeper"

                [[website]]
                domains = ["one.example.com"]
                human_cookie_secure = true
                footer_html = { de = '<a href="/legal">website footer</a>' }
                path_prefix = "/one-check"
                """,
      )

      with patch.dict(
        os.environ,
        {
          "GATEKEEPER_CONFIG_FILE": config_path,
          "GATEKEEPER_VERIFICATION_MODE": "dummy",
          "GATEKEEPER_TRUSTED_PROXY_HOPS": "0",
        },
        clear=True,
      ):
        app = create_app()

    client = app.test_client()
    default_response = client.get(
      "/gatekeeper/challenge",
      base_url="http://localhost",
      headers={"Accept-Language": "de"},
      query_string={"return": "/ok"},
    )
    website_response = client.get(
      "/one-check/challenge",
      base_url="https://one.example.com",
      headers={"Accept-Language": "de"},
      query_string={"return": "/ok"},
    )
    website_fallback_response = client.get(
      "/one-check/challenge",
      base_url="https://one.example.com",
      headers={"Accept-Language": "fr"},
      query_string={"return": "/ok"},
    )

    default_body = default_response.get_data(as_text=True)
    website_body = website_response.get_data(as_text=True)
    website_fallback_body = website_fallback_response.get_data(as_text=True)

    self.assertIn("standard <strong>fuss</strong>", default_body)
    self.assertIn('<a href="/legal">website footer</a>', website_body)
    self.assertIn("default <strong>footer</strong>", website_fallback_body)
    self.assertNotIn("website footer", default_body)
    self.assertNotIn("default <strong>footer</strong>", website_body)

  @patch("app.ratelimit.redis.Redis.from_url")
  def test_valkey_rate_limit_backend_is_used_when_configured(self, redis_from_url):
    fake_script = MagicMock(return_value=[0, 30000])
    fake_client = MagicMock()
    fake_client.register_script.return_value = fake_script
    redis_from_url.return_value = fake_client

    app = self._create_app(
      GATEKEEPER_RATE_LIMIT_BACKEND="valkey",
      GATEKEEPER_RATE_LIMIT_VALKEY_URL="redis://valkey:6379/1",
    )
    response = app.test_client().get(
      "/gatekeeper/challenge",
      base_url="http://localhost",
      query_string={"return": "/ok"},
    )

    self.assertEqual(429, response.status_code)
    redis_from_url.assert_called_once_with("redis://valkey:6379/1")
    fake_script.assert_called_once()

  def test_domain_specific_path_prefix_and_cookie_policy_are_used(self):
    with tempfile.TemporaryDirectory() as temp_dir:
      config_path = self._write_config(
        temp_dir,
        """
                [gatekeeper]
                secret_key = "default-secret"
                human_cookie_secure = false
                path_prefix = "/gatekeeper"

                [[website]]
                domains = ["one.example.com"]
                secret_key = "site-secret"
                human_cookie_secure = true
                path_prefix = "/one-check"
                """,
      )

      with patch.dict(
        os.environ,
        {
          "GATEKEEPER_CONFIG_FILE": config_path,
          "GATEKEEPER_VERIFICATION_MODE": "dummy",
          "GATEKEEPER_TRUSTED_PROXY_HOPS": "0",
        },
        clear=True,
      ):
        app = create_app()

    client = app.test_client()
    website_check = client.get(
      "/one-check/check",
      base_url="https://one.example.com",
      headers={"X-Original-URI": "/ok"},
    )
    default_check = client.get(
      "/gatekeeper/check",
      base_url="http://localhost",
      headers={"X-Original-URI": "/ok"},
    )
    verify_response = client.post(
      "/one-check/verify",
      base_url="https://one.example.com",
      data={"return": "/ok"},
      headers={"User-Agent": "UA"},
    )

    self.assertEqual(401, website_check.status_code)
    self.assertTrue(
      website_check.headers["X-Auth-Redirect"].startswith("/one-check/challenge?")
    )
    self.assertEqual(401, default_check.status_code)
    self.assertTrue(
      default_check.headers["X-Auth-Redirect"].startswith("/gatekeeper/challenge?")
    )
    self.assertTrue(
      verify_response.headers["Set-Cookie"].startswith("__Host-gatekeeper_verified=")
    )

  def test_rate_limits_are_separated_by_website_host(self):
    with tempfile.TemporaryDirectory() as temp_dir:
      config_path = self._write_config(
        temp_dir,
        """
                [gatekeeper]
                secret_key = "default-secret"
                challenge_rate_limit_requests = 1
                challenge_rate_limit_window_seconds = 60
                challenge_rate_limit_block_seconds = 30
                path_prefix = "/gatekeeper"

                [[website]]
                domains = ["one.example.com"]
                human_cookie_secure = true
                path_prefix = "/one-check"

                [[website]]
                domains = ["two.example.com"]
                human_cookie_secure = true
                path_prefix = "/two-check"
                """,
      )

      with patch.dict(
        os.environ,
        {
          "GATEKEEPER_CONFIG_FILE": config_path,
          "GATEKEEPER_VERIFICATION_MODE": "dummy",
          "GATEKEEPER_TRUSTED_PROXY_HOPS": "0",
        },
        clear=True,
      ):
        app = create_app()

    client = app.test_client()

    first_one = client.get(
      "/one-check/challenge",
      base_url="https://one.example.com",
      query_string={"return": "/ok"},
    )
    second_one = client.get(
      "/one-check/challenge",
      base_url="https://one.example.com",
      query_string={"return": "/ok"},
    )
    first_two = client.get(
      "/two-check/challenge",
      base_url="https://two.example.com",
      query_string={"return": "/ok"},
    )

    self.assertEqual(200, first_one.status_code)
    self.assertEqual(429, second_one.status_code)
    self.assertEqual(200, first_two.status_code)

  @patch("app.ratelimit.redis.Redis.from_url")
  def test_global_valkey_backend_is_shared_across_websites(self, redis_from_url):
    fake_script = MagicMock(return_value=[1, 0])
    fake_client = MagicMock()
    fake_client.register_script.return_value = fake_script
    redis_from_url.return_value = fake_client

    with tempfile.TemporaryDirectory() as temp_dir:
      config_path = self._write_config(
        temp_dir,
        """
                [gatekeeper]
                secret_key = "default-secret"
                rate_limit_backend = "auto"
                rate_limit_valkey_url = "redis://shared-valkey:6379/1"
                path_prefix = "/gatekeeper"

                [[website]]
                domains = ["one.example.com"]
                human_cookie_secure = true
                path_prefix = "/one-check"

                [[website]]
                domains = ["two.example.com"]
                human_cookie_secure = true
                path_prefix = "/two-check"
                """,
      )

      with patch.dict(
        os.environ,
        {
          "GATEKEEPER_CONFIG_FILE": config_path,
          "GATEKEEPER_VERIFICATION_MODE": "dummy",
          "GATEKEEPER_TRUSTED_PROXY_HOPS": "0",
        },
        clear=True,
      ):
        app = create_app()

    client = app.test_client()
    response_one = client.get(
      "/one-check/challenge",
      base_url="https://one.example.com",
      query_string={"return": "/ok"},
    )
    response_two = client.get(
      "/two-check/challenge",
      base_url="https://two.example.com",
      query_string={"return": "/ok"},
    )

    self.assertEqual(200, response_one.status_code)
    self.assertEqual(200, response_two.status_code)
    redis_from_url.assert_called_once_with("redis://shared-valkey:6379/1")
    self.assertEqual(2, fake_script.call_count)


if __name__ == "__main__":
  unittest.main()
