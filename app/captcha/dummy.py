from http import HTTPStatus

from flask import Request

from .base import VerificationResult


def verify_request(
  settings: object,
  request: Request,
  client_ip: str,
) -> VerificationResult:
  """Dummy mode accepts every submission after the client-side animation."""
  del settings, request, client_ip
  return VerificationResult(
    success=True,
    retryable=False,
    error_key=None,
    status_code=HTTPStatus.OK,
  )
