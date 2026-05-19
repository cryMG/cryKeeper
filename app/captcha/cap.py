import json
from dataclasses import dataclass
from http import HTTPStatus
from typing import Any
from urllib import error, request

from flask import Request

from .base import VerificationResult, is_allowed_absolute_http_url


@dataclass(frozen=True)
class CapVerificationResult(VerificationResult):
  """Compatibility wrapper for the CAP verifier result."""


def verify_request(
  settings: object,
  flask_request: Request,
  client_ip: str,
) -> CapVerificationResult:
  """Verify the submitted CAP token for one challenge form POST."""
  del client_ip
  cap_response_token = flask_request.form.get("cap-token", "").strip()
  if not cap_response_token:
    return CapVerificationResult(
      success=False,
      retryable=False,
      error_key="error_incomplete",
      status_code=HTTPStatus.BAD_REQUEST,
      message="Missing Cap token during verification.",
      payload=None,
    )

  return verify_token(
    settings.cap_siteverify_url,
    settings.cap_secret_key,
    cap_response_token,
    settings.cap_verify_timeout_seconds,
  )


def verify_token(
  siteverify_url: str,
  secret_key: str,
  response_token: str,
  timeout_seconds: int,
) -> CapVerificationResult:
  """Verify a solved Cap token against Cap's server-side siteverify endpoint."""
  if not is_allowed_absolute_http_url(siteverify_url):
    return CapVerificationResult(
      success=False,
      retryable=False,
      error_key="error_failed",
      status_code=HTTPStatus.FORBIDDEN,
      message="Cap verification URL must use an absolute http or https URL.",
      payload=None,
    )

  payload = json.dumps(
    {
      "secret": secret_key,
      "response": response_token,
    }
  ).encode("utf-8")
  verify_request = request.Request(
    siteverify_url,
    data=payload,
    headers={"Content-Type": "application/json"},
    method="POST",
  )

  try:
    with request.urlopen(verify_request, timeout=timeout_seconds) as response:  # nosec B310
      response_payload = json.loads(response.read())
  except error.HTTPError as exc:
    response_payload = _read_error_payload(exc)
    return CapVerificationResult(
      success=False,
      retryable=False,
      error_key="error_failed",
      status_code=HTTPStatus.FORBIDDEN,
      message=f"Cap verification failed with HTTP {exc.code}.",
      payload=response_payload,
    )
  except (error.URLError, TimeoutError, OSError):
    return CapVerificationResult(
      success=False,
      retryable=True,
      error_key="error_unavailable",
      status_code=HTTPStatus.BAD_GATEWAY,
      message="Cap verification is temporarily unavailable.",
      payload=None,
    )
  except json.JSONDecodeError:
    return CapVerificationResult(
      success=False,
      retryable=True,
      error_key="error_unavailable",
      status_code=HTTPStatus.BAD_GATEWAY,
      message="Cap verification returned an invalid response.",
      payload=None,
    )

  success = bool(response_payload.get("success"))
  if success:
    return CapVerificationResult(
      success=True,
      retryable=False,
      error_key=None,
      status_code=HTTPStatus.OK,
      message=None,
      payload=response_payload,
    )

  return CapVerificationResult(
    success=False,
    retryable=False,
    error_key="error_failed",
    status_code=HTTPStatus.FORBIDDEN,
    message="Cap verification did not succeed.",
    payload=response_payload,
  )


def _read_error_payload(exc: error.HTTPError) -> dict[str, Any] | None:
  """Best-effort decode of error payloads returned by Cap."""
  try:
    return json.loads(exc.read())
  except (OSError, json.JSONDecodeError):
    return None
