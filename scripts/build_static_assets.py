import argparse
import hashlib
import json
import shutil
from pathlib import Path

from rcssmin import cssmin
from rjsmin import jsmin

ENTRY_FILES = (
  "ui.css",
  "dashboard.css",
  "challenge-common.js",
  "challenge-cap.js",
  "challenge-hcaptcha.js",
  "challenge-altcha.js",
  "challenge-dummy.js",
  "verify-redirect.js",
  "dashboard.js",
)


def _minified_contents(source_path: Path) -> str:
  source_text = source_path.read_text(encoding="utf-8")
  if source_path.suffix == ".css":
    return cssmin(source_text)
  if source_path.suffix == ".js":
    return jsmin(source_text)
  raise ValueError(f"Unsupported asset type: {source_path.suffix}")


def build_assets(source_root: Path, output_root: Path) -> dict[str, str]:
  shutil.rmtree(output_root, ignore_errors=True)
  output_root.mkdir(parents=True, exist_ok=True)
  manifest: dict[str, str] = {}

  for logical_name in ENTRY_FILES:
    source_path = source_root / logical_name
    minified_text = _minified_contents(source_path)
    content_hash = hashlib.sha256(minified_text.encode("utf-8")).hexdigest()[:12]
    hashed_name = f"{source_path.stem}-{content_hash}{source_path.suffix}"
    output_path = output_root / hashed_name
    output_path.write_text(minified_text, encoding="utf-8")
    manifest[logical_name] = hashed_name

  (output_root / "asset-manifest.json").write_text(
    json.dumps(manifest, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
  )
  return manifest


def main() -> None:
  parser = argparse.ArgumentParser(
    description="Minify local JS/CSS assets into hashed filenames plus a manifest."
  )
  parser.add_argument(
    "source_root",
    nargs="?",
    default=Path(__file__).resolve().parents[1] / "app" / "static",
    type=Path,
  )
  parser.add_argument(
    "output_root",
    nargs="?",
    default=Path(__file__).resolve().parents[1] / "build" / "static-dist",
    type=Path,
  )
  args = parser.parse_args()

  build_assets(args.source_root, args.output_root)


if __name__ == "__main__":
  main()
