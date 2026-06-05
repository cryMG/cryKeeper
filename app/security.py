import logging
from posixpath import normpath
from urllib.parse import unquote, urlsplit

_LOG = logging.getLogger(__name__)


def normalize_return_path(
  raw_value: str | None,
  blocked_prefixes: tuple[str, ...],
  max_length: int,
  fallback: str = "/",
) -> str:
  """Allow only safe local return paths and fall back to '/' on unsafe input."""
  if not raw_value:
    return fallback

  if len(raw_value) > max_length:
    return fallback

  parsed = urlsplit(raw_value)
  # Reject absolute URLs so challenge redirects cannot send the browser off-site.
  if parsed.scheme or parsed.netloc:
    return fallback

  if not parsed.path.startswith("/") or parsed.path.startswith("//"):
    return fallback

  decoded_path = _fully_unquote_path(parsed.path)
  # Browsers may treat backslashes as forward slashes, so /\evil.com can become //evil.com.
  if "\\" in parsed.path or "\\" in decoded_path:
    return fallback

  if not decoded_path.startswith("/") or decoded_path.startswith("//"):
    return fallback

  canonical_path = _normalize_path_segments(decoded_path)

  for prefix in blocked_prefixes:
    if (
      parsed.path == prefix
      or parsed.path.startswith(f"{prefix}/")
      or decoded_path == prefix
      or decoded_path.startswith(f"{prefix}/")
      or canonical_path == prefix
      or canonical_path.startswith(f"{prefix}/")
    ):
      return fallback

  normalized = parsed.path
  if parsed.query:
    normalized = f"{normalized}?{parsed.query}"
  return normalized


def _fully_unquote_path(value: str) -> str:
  """Decode nested percent-encoding before checking for blocked local paths."""
  decoded_value = value
  for _ in range(8):
    unquoted_value = unquote(decoded_value)
    if unquoted_value == decoded_value:
      break
    decoded_value = unquoted_value
  else:
    _LOG.warning("Path could not be fully unquoted after 8 iterations: %s", value)
  return decoded_value


def _normalize_path_segments(value: str) -> str:
  """Collapse dot-segments so browser path normalization cannot bypass checks."""
  normalized_value = normpath(value)
  if normalized_value == ".":
    return "/"
  if normalized_value.startswith("/"):
    return normalized_value
  return f"/{normalized_value.lstrip('/')}"
