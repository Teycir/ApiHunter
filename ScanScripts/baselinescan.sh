#!/usr/bin/env bash
set -euo pipefail

# Generate a baseline NDJSON file for diffing later.

source "$(dirname "${BASH_SOURCE[0]}")/_scan_common.sh"

parse_input "$@"
ensure_bin

EXTRA_ARGS=()
append_if_missing --format ndjson
append_if_missing --output baseline.ndjson

exec "$SCAN_BIN" "${INPUT_ARGS[@]}" "${EXTRA_ARGS[@]}" "${USER_ARGS[@]}"
