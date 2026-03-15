#!/usr/bin/env bash
set -euo pipefail

# Run a scan with CLI defaults.

source "$(dirname "${BASH_SOURCE[0]}")/_scan_common.sh"

parse_input "$@"
ensure_bin

exec "$SCAN_BIN" "${INPUT_ARGS[@]}" "${USER_ARGS[@]}"
