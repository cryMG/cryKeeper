from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit


@dataclass(frozen=True)
class VerificationResult:
  """Structured provider result so routes can map failures to user-facing errors."""

  success: bool
  retryable: bool
  error_key: str | None = None
  status_code: int = 200
  message: str | None = None
  payload: dict[str, Any] | None = None


def is_allowed_absolute_http_url(url: str) -> bool:
  """Restrict outbound verification targets to absolute HTTP(S) URLs."""
  parsed = urlsplit((url or "").strip())
  return parsed.scheme in {"http", "https"} and bool(parsed.netloc)


def origin_from_url(url: str) -> str | None:
  """Extract a CSP-safe origin from an absolute URL when available."""
  parsed = urlsplit((url or "").strip())
  if not parsed.scheme or not parsed.netloc:
    return None
  return f"{parsed.scheme}://{parsed.netloc}"
