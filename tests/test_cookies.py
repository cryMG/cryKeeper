import unittest

from app.cookies import issue_token_for_client, verify_token_for_client


class CookieRotationTests(unittest.TestCase):
  def test_verify_accepts_token_signed_by_previous_secret_key(self):
    token = issue_token_for_client(
      "old-secret",
      60,
      client_binding="user-agent:ExampleBrowser/1.0",
    )

    payload = verify_token_for_client(
      ("new-secret", "old-secret"),
      token,
      client_binding="user-agent:ExampleBrowser/1.0",
    )

    self.assertIsNotNone(payload)
    self.assertEqual("human", payload["sub"])

  def test_verify_rejects_rotated_token_without_previous_secret_key(self):
    token = issue_token_for_client(
      "old-secret",
      60,
      client_binding="user-agent:ExampleBrowser/1.0",
    )

    payload = verify_token_for_client(
      "new-secret",
      token,
      client_binding="user-agent:ExampleBrowser/1.0",
    )

    self.assertIsNone(payload)

  def test_new_tokens_still_require_the_primary_secret_key(self):
    token = issue_token_for_client(
      "new-secret",
      60,
      client_binding="user-agent:ExampleBrowser/1.0",
    )

    self.assertIsNotNone(
      verify_token_for_client(
        ("new-secret", "old-secret"),
        token,
        client_binding="user-agent:ExampleBrowser/1.0",
      )
    )
    self.assertIsNone(
      verify_token_for_client(
        "old-secret",
        token,
        client_binding="user-agent:ExampleBrowser/1.0",
      )
    )


if __name__ == "__main__":
  unittest.main()
