import base64
import hashlib
import hmac
import json
import time
from typing import Any


def _b64url_encode(value: bytes) -> str:
  """Encode bytes in URL-safe base64 without '=' padding for compact cookies."""
  return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _b64url_decode(value: str) -> bytes:
  """Restore stripped base64 padding before decoding."""
  padding = "=" * (-len(value) % 4)
  return base64.urlsafe_b64decode(value + padding)


def issue_token(secret_key: str, ttl_seconds: int) -> str:
  """Issue a stateless signed cookie payload with an explicit expiry timestamp."""
  return issue_token_for_client(secret_key, ttl_seconds)


def issue_token_for_client(
  secret_key: str,
  ttl_seconds: int,
  client_binding: str | None = None,
) -> str:
  """Issue a stateless signed cookie optionally bound to stable client properties."""
  issued_at = int(time.time())
  payload = {
    "v": 2 if client_binding is not None else 1,
    "sub": "human",
    "iat": issued_at,
    "exp": issued_at + ttl_seconds,
  }
  if client_binding is not None:
    payload["cb"] = _client_binding_digest(secret_key, client_binding)

  # Stable key order and compact separators keep the signed payload deterministic.
  payload_json = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode(
    "utf-8"
  )
  payload_b64 = _b64url_encode(payload_json)
  signature_b64 = _sign(secret_key, payload_b64)
  return f"{payload_b64}.{signature_b64}"


def verify_token(secret_key: str, token: str | None) -> dict[str, Any] | None:
  """Validate signature, shape, and expiry of the human-verification cookie."""
  return verify_token_for_client(secret_key, token)


def verify_token_for_client(
  secret_key: str,
  token: str | None,
  client_binding: str | None = None,
) -> dict[str, Any] | None:
  """Validate signature, expiry, and optional client binding for the cookie."""
  if not token:
    return None

  try:
    payload_b64, signature_b64 = token.split(".", 1)
  except ValueError:
    return None

  expected_signature = _sign(secret_key, payload_b64)
  # Constant-time comparison avoids leaking signature information via timing.
  if not hmac.compare_digest(signature_b64, expected_signature):
    return None

  try:
    payload = json.loads(_b64url_decode(payload_b64))
  except (ValueError, json.JSONDecodeError):
    return None

  if payload.get("v") not in {1, 2}:
    return None

  if payload.get("sub") != "human":
    return None

  expected_binding_digest = None
  if client_binding is not None:
    expected_binding_digest = _client_binding_digest(secret_key, client_binding)
    payload_binding_digest = payload.get("cb")
    if not isinstance(payload_binding_digest, str):
      return None
    if not hmac.compare_digest(payload_binding_digest, expected_binding_digest):
      return None

  expires_at = payload.get("exp")
  if not isinstance(expires_at, int) or expires_at < int(time.time()):
    return None

  return payload


def _client_binding_digest(secret_key: str, client_binding: str) -> str:
  """Derive a deterministic digest for client-bound cookies without exposing raw headers."""
  digest = hmac.new(
    secret_key.encode("utf-8"),
    f"client-binding:{client_binding}".encode("utf-8"),
    hashlib.sha256,
  ).digest()
  return _b64url_encode(digest)


def _sign(secret_key: str, payload_b64: str) -> str:
  """Sign the serialized payload with HMAC-SHA256."""
  digest = hmac.new(
    secret_key.encode("utf-8"),
    payload_b64.encode("ascii"),
    hashlib.sha256,
  ).digest()
  return _b64url_encode(digest)
