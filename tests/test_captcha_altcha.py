import unittest
from unittest.mock import MagicMock, patch

from app.captcha.altcha import verify_payload


class AltchaVerificationTests(unittest.TestCase):
  @patch("app.captcha.altcha._load_altcha_symbols")
  def test_verify_payload_returns_success_on_valid_verification(self, load_altcha):
    create_challenge_func, verify_solution = MagicMock(), MagicMock()
    load_altcha.return_value = (create_challenge_func, verify_solution)

    result_mock = MagicMock()
    result_mock.verified = True
    result_mock.expired = False
    result_mock.invalid_signature = False
    result_mock.invalid_solution = False
    result_mock.error = None
    verify_solution.return_value = result_mock

    result = verify_payload("valid-payload", "hmac-secret", "hmac-key-secret")

    self.assertTrue(result.success)
    self.assertFalse(result.retryable)
    self.assertIsNone(result.error_key)
    self.assertIsNone(result.message)
    self.assertEqual(
      {
        "expired": False,
        "invalid_signature": False,
        "invalid_solution": False,
        "error": None,
      },
      result.payload,
    )

  @patch("app.captcha.altcha._load_altcha_symbols")
  def test_verify_payload_returns_error_on_parse_error(self, load_altcha):
    create_challenge_func, verify_solution = MagicMock(), MagicMock()
    load_altcha.return_value = (create_challenge_func, verify_solution)

    result_mock = MagicMock()
    result_mock.verified = False
    result_mock.expired = True
    result_mock.invalid_signature = True
    result_mock.invalid_solution = True
    result_mock.error = "Invalid payload format"
    verify_solution.return_value = result_mock

    result = verify_payload("invalid-payload", "hmac-secret", "hmac-key-secret")

    self.assertFalse(result.success)
    self.assertFalse(result.retryable)
    self.assertEqual("error_incomplete", result.error_key)
    self.assertEqual("ALTCHA verification payload could not be parsed.", result.message)
    self.assertIn("error", result.payload)
    self.assertEqual("Invalid payload format", result.payload["error"])

  @patch("app.captcha.altcha._load_altcha_symbols")
  def test_verify_payload_returns_error_on_invalid_solution(self, load_altcha):
    create_challenge_func, verify_solution = MagicMock(), MagicMock()
    load_altcha.return_value = (create_challenge_func, verify_solution)

    result_mock = MagicMock()
    result_mock.verified = False
    result_mock.expired = False
    result_mock.invalid_signature = False
    result_mock.invalid_solution = True
    result_mock.error = None
    verify_solution.return_value = result_mock

    result = verify_payload("invalid-solution", "hmac-secret", "hmac-key-secret")

    self.assertFalse(result.success)
    self.assertFalse(result.retryable)
    self.assertEqual("error_failed", result.error_key)
    self.assertEqual("ALTCHA verification did not succeed.", result.message)
    self.assertEqual(
      {
        "expired": False,
        "invalid_signature": False,
        "invalid_solution": True,
        "error": None,
      },
      result.payload,
    )


if __name__ == "__main__":
  unittest.main()
