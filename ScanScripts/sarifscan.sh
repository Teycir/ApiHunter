#!/usr/bin/env bash
set -euo pipefail

# Produce a SARIF report by default.

source "$(dirname "${BASH_SOURCE[0]}")/_scan_common.sh"

parse_input "$@"
ensure_bin

EXTRA_ARGS=()
append_if_missing --format sarif
append_if_missing --output results.sarif

exec "$SCAN_BIN" "${INPUT_ARGS[@]}" "${EXTRA_ARGS[@]}" "${USER_ARGS[@]}"
