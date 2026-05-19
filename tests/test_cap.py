import unittest
from unittest.mock import MagicMock, patch

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


if __name__ == "__main__":
  unittest.main()
