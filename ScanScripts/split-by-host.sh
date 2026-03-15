#!/usr/bin/env bash
set -euo pipefail

# Split a URL list into per-host files and optionally scan them.

usage() {
  echo "Usage: $(basename "$0") <urls_file> [--out-dir DIR] [--scan-cmd CMD] [--jobs N]" >&2
}

if [[ $# -lt 1 ]]; then
  usage
  exit 2
fi

URLS_FILE="$1"
shift

if [[ ! -f "$URLS_FILE" ]]; then
  echo "URL file not found: $URLS_FILE" >&2
  exit 1
fi

OUT_DIR="split-targets"
SCAN_CMD=""
JOBS=4

while [[ $# -gt 0 ]]; do
  case "$1" in
    --out-dir)
      OUT_DIR="$2"
      shift 2
      ;;
    --scan-cmd)
      SCAN_CMD="$2"
      shift 2
      ;;
    --jobs)
      JOBS="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage
      exit 2
      ;;
  esac
done

mkdir -p "$OUT_DIR"

python3 - "$URLS_FILE" "$OUT_DIR" <<'PY'
import os
import sys
from urllib.parse import urlparse

urls_file = sys.argv[1]
out_dir = sys.argv[2]

with open(urls_file, "r", encoding="utf-8") as fh:
    for raw in fh:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parsed = urlparse(line)
        host = parsed.netloc or parsed.path.split("/")[0]
        if not host:
            continue
        safe = host.replace(":", "_")
        path = os.path.join(out_dir, f"{safe}.txt")
        with open(path, "a", encoding="utf-8") as out:
            out.write(line + "\n")
PY

if [[ -n "$SCAN_CMD" ]]; then
  mapfile -t FILES < <(find "$OUT_DIR" -type f -name '*.txt' -print)
  if [[ ${#FILES[@]} -eq 0 ]]; then
    echo "No split files found in $OUT_DIR" >&2
    exit 1
  fi
  printf '%s\n' "${FILES[@]}" | xargs -n1 -P "$JOBS" "$SCAN_CMD"
fi

