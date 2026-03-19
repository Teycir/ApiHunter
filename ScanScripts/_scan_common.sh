#!/usr/bin/env bash
set -euo pipefail

SCAN_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCAN_ROOT_DIR="$(cd "$SCAN_SCRIPT_DIR/.." && pwd)"
SCAN_BIN="$SCAN_ROOT_DIR/target/release/apihunter"

usage_base() {
  echo "Usage: $(basename "$0") <urls_file> [extra args]"
  echo "   or: $(basename "$0") --stdin [extra args]"
}

ensure_bin() {
  if [[ ! -x "$SCAN_BIN" ]]; then
    echo "Binary not found; building release..." >&2
    (cd "$SCAN_ROOT_DIR" && cargo build --release)
  fi
}

parse_input() {
  if [[ $# -eq 0 ]]; then
    usage_base
    exit 2
  fi

  INPUT_ARGS=()
  if [[ "$1" == "--stdin" ]]; then
    INPUT_ARGS+=("--stdin")
    shift
  elif [[ "$1" == -* ]]; then
    usage_base
    exit 2
  else
    URLS_FILE="$1"
    shift
    if [[ ! -f "$URLS_FILE" ]]; then
      echo "URL file not found: $URLS_FILE" >&2
      exit 1
    fi
    INPUT_ARGS+=("--urls" "$URLS_FILE")
  fi

  USER_ARGS=("$@")
}

has_flag() {
  local flag="$1"
  shift
  for arg in "$@"; do
    if [[ "$arg" == "$flag" || "$arg" == "$flag="* ]]; then
      return 0
    fi
  done
  return 1
}

append_if_missing() {
  local flag="$1"
  shift
  if ! has_flag "$flag" "${USER_ARGS[@]}"; then
    EXTRA_ARGS+=("$flag")
    if [[ $# -gt 0 ]]; then
      EXTRA_ARGS+=("$@")
    fi
  fi
}
