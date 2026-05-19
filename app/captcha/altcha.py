import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from http import HTTPStatus
from typing import Any

from flask import Request

from .base import VerificationResult


@dataclass(frozen=True)
class AltchaVerificationResult(VerificationResult):
  """Structured result for ALTCHA verification."""


def create_challenge(settings: object) -> dict[str, Any]:
  """Create one signed ALTCHA challenge for the browser widget."""
  create_challenge_func, _ = _load_altcha_symbols()
  challenge = create_challenge_func(
    algorithm=settings.altcha_algorithm,
    cost=settings.altcha_challenge_cost,
    counter=secrets.randbelow(settings.altcha_challenge_cost)
    + settings.altcha_challenge_cost,
    expires_at=(
      datetime.now(timezone.utc) + timedelta(seconds=settings.altcha_expires_seconds)
    ),
    hmac_secret=settings.altcha_hmac_secret,
    hmac_key_secret=settings.altcha_effective_hmac_key_secret,
  )
  return challenge.to_dict()


def verify_request(
  settings: object,
  flask_request: Request,
  client_ip: str,
) -> AltchaVerificationResult:
  """Verify the submitted ALTCHA payload for one challenge POST."""
  del client_ip
  payload = flask_request.form.get("altcha", "").strip()
  if not payload:
    return AltchaVerificationResult(
      success=False,
      retryable=False,
      error_key="error_incomplete",
      status_code=HTTPStatus.BAD_REQUEST,
      message="Missing ALTCHA payload during verification.",
      payload=None,
    )

  return verify_payload(
    payload,
    settings.altcha_hmac_secret,
    settings.altcha_effective_hmac_key_secret,
  )


def verify_payload(
  payload: str,
  hmac_secret: str,
  hmac_key_secret: str,
) -> AltchaVerificationResult:
  """Verify one ALTCHA payload using the official Python library."""
  _, verify_solution = _load_altcha_symbols()
  result = verify_solution(
    payload,
    hmac_secret,
    hmac_key_secret=hmac_key_secret,
  )
  result_payload = {
    "expired": bool(getattr(result, "expired", False)),
    "invalid_signature": bool(getattr(result, "invalid_signature", False)),
    "invalid_solution": bool(getattr(result, "invalid_solution", False)),
    "error": getattr(result, "error", None),
  }
  if bool(getattr(result, "verified", False)):
    return AltchaVerificationResult(
      success=True,
      retryable=False,
      error_key=None,
      status_code=HTTPStatus.OK,
      message=None,
      payload=result_payload,
    )

  if result_payload["error"]:
    return AltchaVerificationResult(
      success=False,
      retryable=False,
      error_key="error_incomplete",
      status_code=HTTPStatus.BAD_REQUEST,
      message="ALTCHA verification payload could not be parsed.",
      payload=result_payload,
    )

  return AltchaVerificationResult(
    success=False,
    retryable=False,
    error_key="error_failed",
    status_code=HTTPStatus.FORBIDDEN,
    message="ALTCHA verification did not succeed.",
    payload=result_payload,
  )


def _load_altcha_symbols():
  """Import ALTCHA lazily so non-ALTCHA deployments do not require the package."""
  try:
    from altcha import create_challenge as create_challenge_func
    from altcha import verify_solution
  except ImportError as exc:
    try:
      from altcha.v2 import create_challenge as create_challenge_func
      from altcha.v2 import verify_solution
    except ImportError:
      raise RuntimeError(
        "ALTCHA support requires the 'altcha' Python package to be installed."
      ) from exc

  return create_challenge_func, verify_solution
