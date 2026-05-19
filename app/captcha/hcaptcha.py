import json
from dataclasses import dataclass
from http import HTTPStatus
from typing import Any
from urllib import error, parse, request

from flask import Request

from .base import VerificationResult, is_allowed_absolute_http_url


@dataclass(frozen=True)
class HCaptchaVerificationResult(VerificationResult):
  """Structured result for hCaptcha verification."""


def verify_request(
  settings: object,
  flask_request: Request,
  client_ip: str,
) -> HCaptchaVerificationResult:
  """Verify the submitted hCaptcha response token for one challenge POST."""
  response_token = flask_request.form.get("h-captcha-response", "").strip()
  if not response_token:
    return HCaptchaVerificationResult(
      success=False,
      retryable=False,
      error_key="error_incomplete",
      status_code=HTTPStatus.BAD_REQUEST,
      message="Missing hCaptcha token during verification.",
      payload=None,
    )

  return verify_token(
    settings.hcaptcha_verify_url,
    settings.hcaptcha_secret_key,
    settings.hcaptcha_site_key,
    response_token,
    client_ip,
    settings.hcaptcha_verify_timeout_seconds,
  )


def verify_token(
  verify_url: str,
  secret_key: str,
  site_key: str,
  response_token: str,
  client_ip: str,
  timeout_seconds: int,
) -> HCaptchaVerificationResult:
  """Verify a solved hCaptcha token against hCaptcha's siteverify endpoint."""
  if not is_allowed_absolute_http_url(verify_url):
    return HCaptchaVerificationResult(
      success=False,
      retryable=False,
      error_key="error_failed",
      status_code=HTTPStatus.FORBIDDEN,
      message="hCaptcha verification URL must use an absolute http or https URL.",
      payload=None,
    )

  payload = {
    "secret": secret_key,
    "response": response_token,
  }
  if client_ip:
    payload["remoteip"] = client_ip
  if site_key:
    payload["sitekey"] = site_key

  verify_request = request.Request(
    verify_url,
    data=parse.urlencode(payload).encode("utf-8"),
    headers={"Content-Type": "application/x-www-form-urlencoded"},
    method="POST",
  )

  try:
    with request.urlopen(verify_request, timeout=timeout_seconds) as response:  # nosec B310
      response_payload = json.loads(response.read())
  except error.HTTPError as exc:
    response_payload = _read_error_payload(exc)
    return HCaptchaVerificationResult(
      success=False,
      retryable=False,
      error_key="error_failed",
      status_code=HTTPStatus.FORBIDDEN,
      message=f"hCaptcha verification failed with HTTP {exc.code}.",
      payload=response_payload,
    )
  except (error.URLError, TimeoutError, OSError):
    return HCaptchaVerificationResult(
      success=False,
      retryable=True,
      error_key="error_unavailable",
      status_code=HTTPStatus.BAD_GATEWAY,
      message="hCaptcha verification is temporarily unavailable.",
      payload=None,
    )
  except json.JSONDecodeError:
    return HCaptchaVerificationResult(
      success=False,
      retryable=True,
      error_key="error_unavailable",
      status_code=HTTPStatus.BAD_GATEWAY,
      message="hCaptcha verification returned an invalid response.",
      payload=None,
    )

  if bool(response_payload.get("success")):
    return HCaptchaVerificationResult(
      success=True,
      retryable=False,
      error_key=None,
      status_code=HTTPStatus.OK,
      message=None,
      payload=response_payload,
    )

  return HCaptchaVerificationResult(
    success=False,
    retryable=False,
    error_key="error_failed",
    status_code=HTTPStatus.FORBIDDEN,
    message="hCaptcha verification did not succeed.",
    payload=response_payload,
  )


def _read_error_payload(exc: error.HTTPError) -> dict[str, Any] | None:
  """Best-effort decode of error payloads returned by hCaptcha."""
  try:
    return json.loads(exc.read())
  except (OSError, json.JSONDecodeError):
    return None
