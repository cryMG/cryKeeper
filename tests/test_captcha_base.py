import unittest

from app.captcha.base import is_allowed_absolute_http_url, origin_from_url


class CaptchaBaseTests(unittest.TestCase):
  def test_is_allowed_absolute_http_url_allows_http(self):
    """Test that http URLs are allowed."""
    self.assertTrue(is_allowed_absolute_http_url("http://example.com"))

  def test_is_allowed_absolute_http_url_allows_https(self):
    """Test that https URLs are allowed."""
    self.assertTrue(is_allowed_absolute_http_url("https://example.com"))

  def test_is_allowed_absolute_http_url_rejects_file(self):
    """Test that file URLs are rejected."""
    self.assertFalse(is_allowed_absolute_http_url("file:///tmp/test"))

  def test_is_allowed_absolute_http_url_rejects_ftp(self):
    """Test that ftp URLs are rejected."""
    self.assertFalse(is_allowed_absolute_http_url("ftp://example.com"))

  def test_is_allowed_absolute_http_url_rejects_relative(self):
    """Test that relative URLs are rejected."""
    self.assertFalse(is_allowed_absolute_http_url("/relative/path"))

  def test_is_allowed_absolute_http_url_rejects_none(self):
    """Test that None is rejected."""
    self.assertFalse(is_allowed_absolute_http_url(None))

  def test_is_allowed_absolute_http_url_rejects_empty(self):
    """Test that empty string is rejected."""
    self.assertFalse(is_allowed_absolute_http_url(""))

  def test_is_allowed_absolute_http_url_rejects_no_netloc(self):
    """Test that URLs without netloc are rejected."""
    self.assertFalse(is_allowed_absolute_http_url("http://"))

  def test_origin_from_url_returns_origin_for_valid_url(self):
    """Test that origin is extracted from valid URL."""
    result = origin_from_url("https://example.com:443/path")
    self.assertEqual("https://example.com:443", result)

  def test_origin_from_url_returns_none_for_no_scheme(self):
    """Test that None is returned when scheme is missing."""
    result = origin_from_url("example.com/path")
    self.assertIsNone(result)

  def test_origin_from_url_returns_none_for_no_netloc(self):
    """Test that None is returned when netloc is missing."""
    result = origin_from_url("https:///path")
    self.assertIsNone(result)

  def test_origin_from_url_returns_none_for_empty_input(self):
    """Test that None is returned for empty input."""
    result = origin_from_url("")
    self.assertIsNone(result)

  def test_origin_from_url_returns_none_for_none_input(self):
    """Test that None is returned for None input."""
    result = origin_from_url(None)
    self.assertIsNone(result)


if __name__ == "__main__":
  unittest.main()
