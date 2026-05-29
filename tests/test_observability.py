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
    self.assertEqual(302, verify_response.status_code)
    self.assertEqual(204, check_response.status_code)
    self.assertEqual(200, metrics_response.status_code)

    metrics_body = metrics_response.get_data(as_text=True)
    self.assertIn("crykeeper_check_requests_total", metrics_body)
    self.assertIn("crykeeper_challenge_requests_total", metrics_body)
    self.assertIn("crykeeper_verify_attempts_total", metrics_body)
    self.assertIn('host="localhost"', metrics_body)
    self.assertIn('provider="dummy"', metrics_body)
    self.assertIn('outcome="success"', metrics_body)

  def test_dashboard_renders_verify_and_rate_limit_sections(self):
    app = self._create_app(
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

    self.assertEqual(204, bypass_response.status_code)
    self.assertEqual(429, blocked_response.status_code)
    self.assertEqual(200, dashboard_response.status_code)

    dashboard_body = dashboard_response.get_data(as_text=True)
    self.assertIn("cryKeeper Dashboard", dashboard_body)
    self.assertIn("Skip routes", dashboard_body)
    self.assertIn(
      "Requests bypassed by configured skip_routes since startup.", dashboard_body
    )
    self.assertIn("Verify outcomes", dashboard_body)
    self.assertIn("Rate limits", dashboard_body)
    self.assertIn("localhost", dashboard_body)
    self.assertIn("dummy", dashboard_body)
    self.assertIn("/_crykeeper/static/ui.css", dashboard_body)
    self.assertIn("/_crykeeper/static/dashboard.css", dashboard_body)

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
    try:
      self.assertEqual(200, shared_style_response.status_code)
      self.assertEqual(200, dashboard_style_response.status_code)
      self.assertIn("--page-bg", shared_style_response.get_data(as_text=True))
      self.assertIn("dashboard-shell", dashboard_style_response.get_data(as_text=True))
    finally:
      shared_style_response.close()
      dashboard_style_response.close()
