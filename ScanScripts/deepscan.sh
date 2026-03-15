#!/usr/bin/env bash
set -euo pipefail

# Deeper scan profile with more coverage and retries.

source "$(dirname "${BASH_SOURCE[0]}")/_scan_common.sh"

parse_input "$@"
ensure_bin

EXTRA_ARGS=()
append_if_missing --active-checks
append_if_missing --waf-evasion
append_if_missing --adaptive-concurrency
append_if_missing --per-host-clients
append_if_missing --max-endpoints 0
append_if_missing --retries 3
append_if_missing --timeout-secs 20
append_if_missing --delay-ms 200

exec "$SCAN_BIN" "${INPUT_ARGS[@]}" "${EXTRA_ARGS[@]}" "${USER_ARGS[@]}"
