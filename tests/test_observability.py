import os
import unittest
from unittest.mock import patch

from app import create_app


class CryKeeperObservabilityTests(unittest.TestCase):
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

  def test_metrics_endpoint_reports_core_flow_metrics(self):
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
    check_response = client.get(
      "/crykeeper/check",
      base_url="http://localhost",
      headers={"X-Original-URI": "/ok"},
    )
    metrics_response = client.get(
      "/_crykeeper/metrics",
      base_url="http://localhost",
    )

    self.assertEqual(200, challenge_response.status_code)
    self.assertEqual(200, verify_response.status_code)
    self.assertEqual(204, check_response.status_code)
    self.assertEqual(200, metrics_response.status_code)

    metrics_body = metrics_response.get_data(as_text=True)
    self.assertIn("crykeeper_check_requests_total", metrics_body)
    self.assertIn("crykeeper_challenge_requests_total", metrics_body)
    self.assertIn("crykeeper_unsolved_challenge_attempts", metrics_body)
    self.assertIn("crykeeper_request_header_issues_total", metrics_body)
    self.assertIn("crykeeper_verify_attempts_total", metrics_body)
    self.assertIn('host="localhost"', metrics_body)
    self.assertIn('header="x-original-method"', metrics_body)
    self.assertIn('provider="dummy"', metrics_body)
    self.assertIn('outcome="success"', metrics_body)

  def test_dashboard_renders_verify_and_rate_limit_sections(self):
    app = self._create_app(
      CRYKEEPER_FOOTER_HTML="custom footer that should not appear on the dashboard",
      CRYKEEPER_VERIFY_RATE_LIMIT_REQUESTS="1",
      CRYKEEPER_VERIFY_RATE_LIMIT_WINDOW_SECONDS="60",
      CRYKEEPER_VERIFY_RATE_LIMIT_BLOCK_SECONDS="60",
      CRYKEEPER_SKIP_ROUTES="GET=^/skip$",
    )
    client = app.test_client()

    bypass_response = client.get(
      "/crykeeper/check",
      base_url="http://localhost",
      headers={
        "X-Original-Method": "GET",
        "X-Original-URI": "/skip",
      },
    )

    client.post(
      "/crykeeper/verify",
      base_url="http://localhost",
      data={"return": "/ok"},
    )
    blocked_response = client.post(
      "/crykeeper/verify",
      base_url="http://localhost",
      data={"return": "/ok"},
    )
    dashboard_response = client.get(
      "/_crykeeper/dashboard",
      base_url="http://localhost",
    )
    metrics_response = client.get(
      "/_crykeeper/metrics",
      base_url="http://localhost",
    )

    self.assertEqual(204, bypass_response.status_code)
    self.assertEqual(429, blocked_response.status_code)
    self.assertEqual(200, dashboard_response.status_code)
    self.assertEqual(200, metrics_response.status_code)

    dashboard_body = dashboard_response.get_data(as_text=True)
    metrics_body = metrics_response.get_data(as_text=True)
    self.assertIn("cryKeeper Dashboard", dashboard_body)
    self.assertIn("Skip routes", dashboard_body)
    self.assertIn("Unsolved challenges", dashboard_body)
    self.assertIn(
      "Explicit challenge attempts without success since startup. Abandoned pages are not observable.",
      dashboard_body,
    )
    self.assertIn(
      "Requests bypassed by configured skip_routes since startup.", dashboard_body
    )
    self.assertNotIn('http-equiv="refresh"', dashboard_body)
    self.assertIn("Verify outcomes", dashboard_body)
    self.assertIn("Rate limits", dashboard_body)
    self.assertIn("Runtime warnings", dashboard_body)
    self.assertIn("Trusted proxy hops are disabled", dashboard_body)
    self.assertIn("trusted_proxy_hops=0", dashboard_body)
    self.assertIn("localhost", dashboard_body)
    self.assertIn("dummy", dashboard_body)
    self.assertIn("data-dashboard-root", dashboard_body)
    self.assertIn("data-manual-refresh", dashboard_body)
    self.assertIn("data-refresh-shell", dashboard_body)
    self.assertIn("data-refresh-status-text", dashboard_body)
    self.assertIn('aria-label="Refresh dashboard"', dashboard_body)
    self.assertIn('viewBox="0 0 24 24"', dashboard_body)
    self.assertIn("/_crykeeper/metrics", dashboard_body)
    self.assertIn("/_crykeeper/static/ui.css", dashboard_body)
    self.assertIn("/_crykeeper/static/dashboard.css", dashboard_body)
    self.assertIn("/_crykeeper/static/dashboard.js", dashboard_body)
    self.assertIn(
      'Powered by <a href="https://github.com/cryMG/cryKeeper"',
      dashboard_body,
    )
    self.assertNotIn(
      "custom footer that should not appear on the dashboard",
      dashboard_body,
    )
    self.assertIn("crykeeper_unsolved_challenge_attempts_total", metrics_body)
    self.assertIn('reason="rate_limited"', metrics_body)

  def test_dashboard_surfaces_runtime_tls_and_header_warnings(self):
    app = self._create_app(
      CRYKEEPER_HUMAN_COOKIE_SECURE="true",
    )
    client = app.test_client()

    check_response = client.get(
      "/crykeeper/check",
      base_url="http://localhost",
      headers={"User-Agent": ""},
    )
    challenge_response = client.get(
      "/crykeeper/challenge",
      base_url="http://example.com",
      query_string={"return": "/ok"},
    )
    dashboard_response = client.get(
      "/_crykeeper/dashboard",
      base_url="http://localhost",
    )

    self.assertEqual(401, check_response.status_code)
    self.assertEqual(400, challenge_response.status_code)
    self.assertEqual(200, dashboard_response.status_code)

    dashboard_body = dashboard_response.get_data(as_text=True)
    self.assertIn("Missing auth_request headers observed", dashboard_body)
    self.assertIn("proxy and auth_request headers", dashboard_body)
    self.assertIn("user-agent 1", dashboard_body)
    self.assertIn("x-forwarded-for 1", dashboard_body)
    self.assertIn("x-forwarded-proto 1", dashboard_body)
    self.assertIn("x-original-method 1", dashboard_body)
    self.assertIn("x-original-uri 1", dashboard_body)
    self.assertIn("Insecure transport rejections observed", dashboard_body)
    self.assertIn("trusted_proxy_hops", dashboard_body)

  def test_dashboard_surfaces_missing_host_header_warning(self):
    app = self._create_app()
    client = app.test_client()

    check_response = client.get(
      "/crykeeper/check",
      base_url="http://localhost",
      headers={
        "Host": "",
        "User-Agent": "UA",
        "X-Forwarded-For": "203.0.113.10",
        "X-Forwarded-Proto": "https",
        "X-Original-Method": "GET",
        "X-Original-URI": "/ok",
      },
      environ_overrides={"HTTP_HOST": ""},
    )
    dashboard_response = client.get(
      "/_crykeeper/dashboard",
      base_url="http://localhost",
    )

    self.assertEqual(401, check_response.status_code)
    self.assertEqual(200, dashboard_response.status_code)

    dashboard_body = dashboard_response.get_data(as_text=True)
    self.assertIn("Missing auth_request headers observed", dashboard_body)
    self.assertIn("host 1", dashboard_body)

  def test_dashboard_does_not_warn_for_legitimate_local_cap_http_override(self):
    app = self._create_app(
      CRYKEEPER_VERIFICATION_MODE="cap",
      CRYKEEPER_HUMAN_COOKIE_SECURE="false",
      CRYKEEPER_ALLOW_INSECURE_LOCAL_CAP="true",
      CRYKEEPER_TRUSTED_PROXY_HOPS="1",
      CRYKEEPER_TRUSTED_PROXY_CIDRS="10.0.0.0/8",
      CRYKEEPER_CAP_PUBLIC_BASE_URL="http://localhost:3000",
      CRYKEEPER_CAP_SITE_KEY="site-key",
      CRYKEEPER_CAP_SECRET_KEY="secret-key",
    )

    dashboard_response = app.test_client().get(
      "/_crykeeper/dashboard",
      base_url="http://localhost",
    )

    self.assertEqual(200, dashboard_response.status_code)
    dashboard_body = dashboard_response.get_data(as_text=True)
    self.assertIn("No runtime warnings detected", dashboard_body)
    self.assertNotIn("allow_insecure_local_cap", dashboard_body)
    self.assertNotIn("Local real-captcha HTTP override is active", dashboard_body)

  def test_metrics_are_not_served_below_public_path_prefix(self):
    app = self._create_app()

    response = app.test_client().get(
      "/crykeeper/metrics",
      base_url="http://localhost",
    )

    self.assertEqual(404, response.status_code)

  def test_observability_static_stylesheets_are_served(self):
    app = self._create_app()
    client = app.test_client()

    shared_style_response = client.get(
      "/_crykeeper/static/ui.css",
      base_url="http://localhost",
    )
    dashboard_style_response = client.get(
      "/_crykeeper/static/dashboard.css",
      base_url="http://localhost",
    )
    dashboard_script_response = client.get(
      "/_crykeeper/static/dashboard.js",
      base_url="http://localhost",
    )
    try:
      self.assertEqual(200, shared_style_response.status_code)
      self.assertEqual(200, dashboard_style_response.status_code)
      self.assertEqual(200, dashboard_script_response.status_code)
      self.assertIn("--page-bg", shared_style_response.get_data(as_text=True))
      self.assertIn(
        "data-refresh-status-text",
        dashboard_body := app.test_client()
        .get(
          "/_crykeeper/dashboard",
          base_url="http://localhost",
        )
        .get_data(as_text=True),
      )
      self.assertIn("dashboard-shell", dashboard_style_response.get_data(as_text=True))
      self.assertIn(
        "data-refresh-shell", dashboard_style_response.get_data(as_text=True)
      )
      self.assertIn(
        "startDashboardRefresh", dashboard_script_response.get_data(as_text=True)
      )
      self.assertIn("data-manual-refresh", dashboard_body)
      self.assertIn(
        "setRefreshButtonState", dashboard_script_response.get_data(as_text=True)
      )
    finally:
      shared_style_response.close()
      dashboard_style_response.close()
      dashboard_script_response.close()
