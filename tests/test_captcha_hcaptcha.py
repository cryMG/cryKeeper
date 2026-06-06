import io
import unittest
from unittest.mock import MagicMock, patch
from urllib import error

from app.captcha.hcaptcha import verify_token


class HCaptchaVerificationTests(unittest.TestCase):
  def test_verify_token_rejects_non_http_schemes(self):
    for verify_url in (
      "file:///tmp/siteverify",
      "ftp://api.hcaptcha.com/siteverify",
    ):
      with self.subTest(verify_url=verify_url):
        result = verify_token(
          verify_url,
          "secret-key",
          "site-key",
          "response-token",
          "203.0.113.5",
          5,
        )

        self.assertFalse(result.success)
        self.assertFalse(result.retryable)
        self.assertEqual(
          "hCaptcha verification URL must use an absolute http or https URL.",
          result.message,
        )
        self.assertIsNone(result.payload)

  @patch("app.captcha.hcaptcha.request.urlopen")
  def test_verify_token_allows_https_siteverify_requests(self, urlopen):
    response = MagicMock()
    response.read.return_value = b'{"success": true}'
    urlopen.return_value.__enter__.return_value = response

    result = verify_token(
      "https://api.hcaptcha.com/siteverify",
      "secret-key",
      "site-key",
      "response-token",
      "203.0.113.5",
      5,
    )

    self.assertTrue(result.success)
    self.assertFalse(result.retryable)
    self.assertEqual({"success": True}, result.payload)
    self.assertEqual(5, urlopen.call_args.kwargs["timeout"])

  @patch("app.captcha.hcaptcha.request.urlopen")
  def test_verify_token_returns_retryable_on_timeout(self, urlopen):
    urlopen.side_effect = TimeoutError("Request timeout")

    result = verify_token(
      "https://api.hcaptcha.com/siteverify",
      "secret-key",
      "site-key",
      "response-token",
      "203.0.113.5",
      5,
    )

    self.assertFalse(result.success)
    self.assertTrue(result.retryable)
    self.assertEqual(
      "hCaptcha verification is temporarily unavailable.", result.message
    )
    self.assertIsNone(result.payload)

  @patch("app.captcha.hcaptcha.request.urlopen")
  def test_verify_token_returns_retryable_on_transport_error(self, urlopen):
    urlopen.side_effect = error.URLError("connection failed")

    result = verify_token(
      "https://api.hcaptcha.com/siteverify",
      "secret-key",
      "site-key",
      "response-token",
      "203.0.113.5",
      5,
    )

    self.assertFalse(result.success)
    self.assertTrue(result.retryable)
    self.assertEqual(
      "hCaptcha verification is temporarily unavailable.",
      result.message,
    )
    self.assertIsNone(result.payload)

  @patch("app.captcha.hcaptcha.request.urlopen")
  def test_verify_token_returns_retryable_on_invalid_json(self, urlopen):
    response = MagicMock()
    response.read.return_value = b"{"
    urlopen.return_value.__enter__.return_value = response

    result = verify_token(
      "https://api.hcaptcha.com/siteverify",
      "secret-key",
      "site-key",
      "response-token",
      "203.0.113.5",
      5,
    )

    self.assertFalse(result.success)
    self.assertTrue(result.retryable)
    self.assertEqual(
      "hCaptcha verification returned an invalid response.",
      result.message,
    )
    self.assertIsNone(result.payload)

  @patch("app.captcha.hcaptcha.request.urlopen")
  def test_verify_token_returns_payload_on_http_error(self, urlopen):
    urlopen.side_effect = error.HTTPError(
      "https://api.hcaptcha.com/siteverify",
      400,
      "Bad Request",
      hdrs=None,
      fp=io.BytesIO(b'{"success": false, "error-codes": ["bad-request"]}'),
    )

    result = verify_token(
      "https://api.hcaptcha.com/siteverify",
      "secret-key",
      "site-key",
      "response-token",
      "203.0.113.5",
      5,
    )

    self.assertFalse(result.success)
    self.assertFalse(result.retryable)
    self.assertEqual(
      "hCaptcha verification failed with HTTP 400.",
      result.message,
    )
    self.assertEqual(
      {"success": False, "error-codes": ["bad-request"]},
      result.payload,
    )


if __name__ == "__main__":
  unittest.main()
