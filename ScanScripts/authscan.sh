#!/usr/bin/env bash
set -euo pipefail

# Scan with auth flows (recommended for authenticated endpoints and IDOR checks).

source "$(dirname "${BASH_SOURCE[0]}")/_scan_common.sh"

parse_input "$@"

if ! has_flag --auth-flow "${USER_ARGS[@]}"; then
  echo "Missing --auth-flow <file>." >&2
  echo "Usage: $(basename "$0") <urls_file|--stdin> --auth-flow flow.json [extra args]" >&2
  exit 2
fi

ensure_bin

EXTRA_ARGS=()
append_if_missing --active-checks
append_if_missing --waf-evasion
append_if_missing --retries 2
append_if_missing --timeout-secs 15
append_if_missing --delay-ms 150

exec "$SCAN_BIN" "${INPUT_ARGS[@]}" "${EXTRA_ARGS[@]}" "${USER_ARGS[@]}"
