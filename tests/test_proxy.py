import unittest

from app.proxy import TrustedProxyHeadersMiddleware


class TrustedProxyHeadersMiddlewareTests(unittest.TestCase):
  def _dummy_app(self, environ, start_response):
    return start_response("200 OK", [])

  def _dummy_start_response(self, *args):
    return None

  def test_removes_forwarded_headers_for_untrusted_ips(self):
    """Test that forwarded headers are stripped for untrusted IPs."""
    middleware = TrustedProxyHeadersMiddleware(self._dummy_app, ("10.0.0.0/8",))

    environ = {"REMOTE_ADDR": "192.168.1.100", "HTTP_X_FORWARDED_FOR": "10.0.0.1"}

    middleware(environ, self._dummy_start_response)

    # Headers should be removed
    self.assertIsNone(environ.get("HTTP_X_FORWARDED_FOR"))

  def test_keeps_forwarded_headers_for_trusted_ips(self):
    """Test that forwarded headers are kept for trusted IPs."""
    middleware = TrustedProxyHeadersMiddleware(self._dummy_app, ("192.168.1.0/24",))

    environ = {"REMOTE_ADDR": "192.168.1.100", "HTTP_X_FORWARDED_FOR": "10.0.0.1"}

    middleware(environ, self._dummy_start_response)

    # Headers should be kept
    self.assertEqual("10.0.0.1", environ.get("HTTP_X_FORWARDED_FOR"))

  def test_remote_addr_is_trusted_returns_false_for_none(self):
    """Test that None remote_addr returns False."""
    middleware = TrustedProxyHeadersMiddleware(self._dummy_app, ("0.0.0.0/0",))
    self.assertFalse(middleware._remote_addr_is_trusted(None))

  def test_remote_addr_is_trusted_returns_false_for_empty_string(self):
    """Test that empty string remote_addr returns False."""
    middleware = TrustedProxyHeadersMiddleware(self._dummy_app, ("0.0.0.0/0",))
    self.assertFalse(middleware._remote_addr_is_trusted(""))

  def test_remote_addr_is_trusted_returns_false_for_whitespace_only(self):
    """Test that whitespace-only remote_addr returns False."""
    middleware = TrustedProxyHeadersMiddleware(self._dummy_app, ("0.0.0.0/0",))
    self.assertFalse(middleware._remote_addr_is_trusted("   "))

  def test_remote_addr_is_trusted_returns_false_for_invalid_ip(self):
    """Test that invalid IP addresses return False."""
    middleware = TrustedProxyHeadersMiddleware(self._dummy_app, ("0.0.0.0/0",))
    self.assertFalse(middleware._remote_addr_is_trusted("invalid-ip"))


if __name__ == "__main__":
  unittest.main()
