import json
import logging
from functools import lru_cache
from pathlib import Path

_ASSET_MANIFEST_FILE = "asset-manifest.json"
HASHED_ASSET_CACHE_MAX_AGE_SECONDS = 14 * 24 * 60 * 60
_LOG = logging.getLogger(__name__)


def _manifest_path() -> Path:
  """Return the optional build-time asset manifest path."""
  return Path(__file__).resolve().parent / "static" / _ASSET_MANIFEST_FILE


@lru_cache(maxsize=1)
def load_asset_manifest() -> dict[str, str]:
  """Load the optional logical-to-hashed asset mapping for local static files."""
  manifest_path = _manifest_path()
  try:
    payload = json.loads(manifest_path.read_text(encoding="utf-8"))
  except FileNotFoundError:
    return {}
  except json.JSONDecodeError:
    _LOG.warning("Ignoring invalid asset manifest at %s", manifest_path)
    return {}

  if not isinstance(payload, dict):
    _LOG.warning("Ignoring unexpected asset manifest payload at %s", manifest_path)
    return {}

  manifest: dict[str, str] = {}
  for logical_name, resolved_name in payload.items():
    if not isinstance(logical_name, str) or not isinstance(resolved_name, str):
      continue
    manifest[logical_name] = resolved_name
  return manifest


def resolved_asset_name(logical_name: str) -> str:
  """Return the build-time hashed asset name when a manifest is available."""
  return load_asset_manifest().get(logical_name, logical_name)


def hashed_asset_cache_control(filename: str | None) -> str | None:
  """Return the cache policy for one manifest-resolved hashed asset filename."""
  if not filename:
    return None
  if filename not in load_asset_manifest().values():
    return None
  return f"public, max-age={HASHED_ASSET_CACHE_MAX_AGE_SECONDS}, immutable"
