import unittest

from app.security import (
  _fully_unquote_path,
  _normalize_path_segments,
  normalize_return_path,
)


class SecurityPathNormalizationTests(unittest.TestCase):
  def test_normalize_return_path_returns_fallback_for_empty_input(self):
    """Test that empty input returns fallback."""
    result = normalize_return_path("", ("/internal",), 100, "/")
    self.assertEqual("/", result)

  def test_normalize_return_path_returns_fallback_for_none_input(self):
    """Test that None input returns fallback."""
    result = normalize_return_path(None, ("/internal",), 100, "/")
    self.assertEqual("/", result)

  def test_normalize_return_path_returns_fallback_for_max_length_exceeded(self):
    """Test that overly long input returns fallback."""
    long_path = "/a" * 1000
    result = normalize_return_path(long_path, ("/internal",), 10, "/")
    self.assertEqual("/", result)

  def test_normalize_return_path_returns_fallback_for_absolute_url(self):
    """Test that absolute URLs are rejected."""
    result = normalize_return_path("https://evil.com", ("/internal",), 100, "/")
    self.assertEqual("/", result)

  def test_normalize_return_path_returns_fallback_for_netloc(self):
    """Test that URLs with netloc are rejected."""
    result = normalize_return_path("//evil.com", ("/internal",), 100, "/")
    self.assertEqual("/", result)

  def test_normalize_return_path_returns_fallback_for_non_slash_start(self):
    """Test that paths not starting with / are rejected."""
    result = normalize_return_path("relative/path", ("/internal",), 100, "/")
    self.assertEqual("/", result)

  def test_normalize_return_path_returns_fallback_for_double_slash_start(self):
    """Test that paths starting with // are rejected."""
    result = normalize_return_path("//evil.com", ("/internal",), 100, "/")
    self.assertEqual("/", result)

  def test_normalize_return_path_returns_fallback_for_backslash_in_path(self):
    """Test that backslashes in path are rejected."""
    result = normalize_return_path("/path\\to\\file", ("/internal",), 100, "/")
    self.assertEqual("/", result)

  def test_normalize_return_path_returns_fallback_for_backslash_in_decoded_path(self):
    """Test that backslashes in decoded path are rejected."""
    result = normalize_return_path("/path%5Cto%5Cfile", ("/internal",), 100, "/")
    self.assertEqual("/", result)

  def test_normalize_return_path_returns_fallback_for_decoded_double_slash_start(self):
    """Test that decoded paths starting with // are rejected."""
    result = normalize_return_path("/%2F%2Fevil.com", ("/internal",), 100, "/")
    self.assertEqual("/", result)

  def test_normalize_return_path_returns_fallback_for_blocked_prefix(self):
    """Test that blocked prefixes are rejected."""
    result = normalize_return_path("/internal/path", ("/internal",), 100, "/")
    self.assertEqual("/", result)

  def test_normalize_return_path_returns_fallback_for_exact_blocked_prefix(self):
    """Test that exact blocked prefix is rejected."""
    result = normalize_return_path("/internal", ("/internal",), 100, "/")
    self.assertEqual("/", result)

  def test_normalize_return_path_returns_fallback_for_query_with_blocked_prefix(self):
    """Test that query parameters with blocked prefix are rejected."""
    result = normalize_return_path("/internal?param=value", ("/internal",), 100, "/")
    self.assertEqual("/", result)

  def test_normalize_return_path_returns_path_with_query_allowed(self):
    """Test that query parameters are preserved for allowed paths."""
    result = normalize_return_path("/allowed?param=value", ("/internal",), 100, "/")
    self.assertEqual("/allowed?param=value", result)

  def test_fully_unquote_path_warns_on_max_iterations(self):
    """Test that warning is logged when max iterations is reached."""
    from unittest.mock import patch

    with patch("app.security._LOG") as mock_log:
      # Create nested encoding that requires >8 iterations to fully decode
      # Each layer of %25 is a double-encoded %
      nested_encoded = "%252525252525252525"  # 9 layers of %25 = requires 10 iterations
      _fully_unquote_path(nested_encoded)
      mock_log.warning.assert_called_once()
      self.assertIn("could not be fully unquoted", mock_log.warning.call_args[0][0])

  def test_normalize_path_segments_returns_slash_for_current_dir(self):
    """Test that '.' is normalized to '/'."""
    result = _normalize_path_segments(".")
    self.assertEqual("/", result)

  def test_normalize_path_segments_adds_slash_prefix_for_relative_path(self):
    """Test that relative paths get '/' prefix."""
    result = _normalize_path_segments("relative/path")
    self.assertEqual("/relative/path", result)

  def test_normalize_path_segments_preserves_absolute_path(self):
    """Test that absolute paths are preserved."""
    result = _normalize_path_segments("/absolute/path")
    self.assertEqual("/absolute/path", result)


if __name__ == "__main__":
  unittest.main()
