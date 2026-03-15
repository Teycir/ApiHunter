#!/usr/bin/env bash
set -euo pipefail

# Run a scan and emit only findings new to a baseline file.

source "$(dirname "${BASH_SOURCE[0]}")/_scan_common.sh"

parse_input "$@"

if [[ ${#USER_ARGS[@]} -lt 1 ]]; then
  echo "Usage: $(basename "$0") <urls_file|--stdin> <baseline.ndjson> [extra args]" >&2
  exit 2
fi

BASELINE_FILE="${USER_ARGS[0]}"
USER_ARGS=("${USER_ARGS[@]:1}")

if [[ ! -f "$BASELINE_FILE" ]]; then
  echo "Baseline file not found: $BASELINE_FILE" >&2
  exit 1
fi

ensure_bin

EXTRA_ARGS=()
append_if_missing --baseline "$BASELINE_FILE"
append_if_missing --format ndjson
append_if_missing --output new-findings.ndjson

exec "$SCAN_BIN" "${INPUT_ARGS[@]}" "${EXTRA_ARGS[@]}" "${USER_ARGS[@]}"
