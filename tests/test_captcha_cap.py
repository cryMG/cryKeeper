import unittest
from unittest.mock import MagicMock, patch
from urllib import error

from app.captcha.cap import verify_token


class CapVerificationTests(unittest.TestCase):
  def test_verify_token_rejects_non_http_schemes(self):
    for siteverify_url in (
      "file:///tmp/siteverify",
      "ftp://cap.example.com/siteverify",
    ):
      with self.subTest(siteverify_url=siteverify_url):
        result = verify_token(siteverify_url, "secret-key", "response-token", 5)

        self.assertFalse(result.success)
        self.assertFalse(result.retryable)
        self.assertEqual(
          "Cap verification URL must use an absolute http or https URL.",
          result.message,
        )
        self.assertIsNone(result.payload)

  @patch("app.captcha.cap.request.urlopen")
  def test_verify_token_allows_https_siteverify_requests(self, urlopen):
    response = MagicMock()
    response.read.return_value = b'{"success": true}'
    urlopen.return_value.__enter__.return_value = response

    result = verify_token(
      "https://cap.example.com/siteverify", "secret-key", "response-token", 5
    )

    self.assertTrue(result.success)
    self.assertFalse(result.retryable)
    self.assertEqual({"success": True}, result.payload)
    self.assertEqual(5, urlopen.call_args.kwargs["timeout"])

  @patch("app.captcha.cap.request.urlopen")
  def test_verify_token_returns_retryable_on_http_error(self, urlopen):
    http_error = error.HTTPError(
      "https://cap.example.com/siteverify",
      503,
      "Service Unavailable",
      {},
      None,
    )
    urlopen.side_effect = http_error

    result = verify_token(
      "https://cap.example.com/siteverify", "secret-key", "response-token", 5
    )

    self.assertFalse(result.success)
    self.assertFalse(result.retryable)
    self.assertIn("HTTP 503", result.message)
    self.assertIsNone(result.payload)

  @patch("app.captcha.cap.request.urlopen")
  def test_verify_token_returns_retryable_on_url_error(self, urlopen):
    urlopen.side_effect = error.URLError("Connection refused")

    result = verify_token(
      "https://cap.example.com/siteverify", "secret-key", "response-token", 5
    )

    self.assertFalse(result.success)
    self.assertTrue(result.retryable)
    self.assertEqual("Cap verification is temporarily unavailable.", result.message)
    self.assertIsNone(result.payload)

  @patch("app.captcha.cap.request.urlopen")
  def test_verify_token_returns_retryable_on_timeout(self, urlopen):
    urlopen.side_effect = TimeoutError("Request timeout")

    result = verify_token(
      "https://cap.example.com/siteverify", "secret-key", "response-token", 5
    )

    self.assertFalse(result.success)
    self.assertTrue(result.retryable)
    self.assertEqual("Cap verification is temporarily unavailable.", result.message)
    self.assertIsNone(result.payload)

  @patch("app.captcha.cap.request.urlopen")
  def test_verify_token_returns_retryable_on_invalid_json(self, urlopen):
    response = MagicMock()
    response.read.return_value = b"invalid json"
    urlopen.return_value.__enter__.return_value = response

    result = verify_token(
      "https://cap.example.com/siteverify", "secret-key", "response-token", 5
    )

    self.assertFalse(result.success)
    self.assertTrue(result.retryable)
    self.assertEqual("Cap verification returned an invalid response.", result.message)
    self.assertIsNone(result.payload)

  @patch("app.captcha.cap.request.urlopen")
  def test_verify_token_returns_payload_on_http_error(self, urlopen):
    error_response = MagicMock()
    error_response.read.return_value = b'{"error": "invalid-token"}'
    http_error = error.HTTPError(
      "https://cap.example.com/siteverify",
      400,
      "Bad Request",
      {},
      error_response,
    )
    urlopen.side_effect = http_error

    result = verify_token(
      "https://cap.example.com/siteverify", "secret-key", "response-token", 5
    )

    self.assertFalse(result.success)
    self.assertFalse(result.retryable)
    self.assertIn("HTTP 400", result.message)
    self.assertEqual({"error": "invalid-token"}, result.payload)


if __name__ == "__main__":
  unittest.main()
