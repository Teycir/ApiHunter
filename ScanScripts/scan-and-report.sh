#!/usr/bin/env bash
set -euo pipefail

# Run a scan and print the latest auto-saved report location.

source "$(dirname "${BASH_SOURCE[0]}")/_scan_common.sh"

parse_input "$@"
ensure_bin

set +e
"$SCAN_BIN" "${INPUT_ARGS[@]}" "${USER_ARGS[@]}"
EXIT_CODE=$?
set -e

REPORT_BASE="$HOME/Documents/ApiHunterReports"
if [[ -d "$REPORT_BASE" ]]; then
  LATEST_DIR=$(ls -dt "$REPORT_BASE"/* 2>/dev/null | head -n1 || true)
  if [[ -n "$LATEST_DIR" ]]; then
    echo "Latest report: $LATEST_DIR"
    if [[ -f "$LATEST_DIR/summary.md" ]]; then
      echo "Summary: $LATEST_DIR/summary.md"
    fi
    if [[ -f "$LATEST_DIR/findings.json" ]]; then
      echo "Findings: $LATEST_DIR/findings.json"
    fi
  fi
fi

exit "$EXIT_CODE"
