#!/usr/bin/env bash
set -euo pipefail

# Re-scan a list of previously inaccessible URLs with slower settings.

source "$(dirname "${BASH_SOURCE[0]}")/_scan_common.sh"

parse_input "$@"
ensure_bin

EXTRA_ARGS=()
append_if_missing --no-filter
append_if_missing --concurrency 5
append_if_missing --timeout-secs 20
append_if_missing --retries 3
append_if_missing --delay-ms 300

exec "$SCAN_BIN" "${INPUT_ARGS[@]}" "${EXTRA_ARGS[@]}" "${USER_ARGS[@]}"
