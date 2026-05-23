#!/usr/bin/env bash
# Run triage regression test suite against 200 stable targets
#
# Usage:
#   ./scripts/run-triage-regression.sh
#   ./scripts/run-triage-regression.sh --custom targets/my-list.txt

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

cd "$PROJECT_ROOT"

# Parse args
CUSTOM_TARGET_FILE=""
if [[ "${1:-}" == "--custom" ]] && [[ -n "${2:-}" ]]; then
    CUSTOM_TARGET_FILE="$2"
fi

echo "=== ApiHunter Triage Regression Suite ==="
echo

if [[ -n "$CUSTOM_TARGET_FILE" ]]; then
    echo "Using custom target file: $CUSTOM_TARGET_FILE"
    export APIHUNTER_TRIAGE_REGRESSION_FILE="$CUSTOM_TARGET_FILE"
else
    echo "Using default target file: targets/triage-regression-200.txt"
fi

echo
echo "Running regression tests (this will take several minutes)..."
echo

# Run all regression tests
cargo test --test triage_regression -- --ignored --nocapture

echo
echo "=== Regression Suite Complete ==="
