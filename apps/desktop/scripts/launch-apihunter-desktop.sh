#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
desktop_dir="$(cd "${script_dir}/.." && pwd)"
binary="${desktop_dir}/src-tauri/target/release/apihunter-desktop"

if [[ ! -x "${binary}" ]]; then
  echo "ApiHunter Desktop binary not found at: ${binary}" >&2
  echo "Build it first with: cd ${desktop_dir} && npm run tauri build" >&2
  exit 1
fi

exec "${binary}" "$@"
