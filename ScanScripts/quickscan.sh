#!/usr/bin/env bash
set -euo pipefail

# Fast, low-impact scan profile.

source "$(dirname "${BASH_SOURCE[0]}")/_scan_common.sh"

parse_input "$@"
ensure_bin

EXTRA_ARGS=()
append_if_missing --concurrency 10
append_if_missing --max-endpoints 20
append_if_missing --timeout-secs 5
append_if_missing --retries 0
append_if_missing --delay-ms 50

exec "$SCAN_BIN" "${INPUT_ARGS[@]}" "${EXTRA_ARGS[@]}" "${USER_ARGS[@]}"
