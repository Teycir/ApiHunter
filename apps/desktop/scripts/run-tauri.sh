#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
desktop_dir="$(cd "${script_dir}/.." && pwd)"
tauri_cli="${desktop_dir}/node_modules/@tauri-apps/cli/tauri.js"

if [[ ! -f "${tauri_cli}" ]]; then
  echo "error: missing Tauri CLI at ${tauri_cli}. Run npm install first." >&2
  exit 1
fi

sanitize_colon_list() {
  local value="$1"
  local result=""
  local item=""
  IFS=':' read -r -a parts <<< "${value}"
  for item in "${parts[@]}"; do
    if [[ "${item}" == *"/snap/"* ]]; then
      continue
    fi
    result="${result:+${result}:}${item}"
  done
  printf '%s' "${result}"
}

# Build a clean environment to keep snap-injected runtime libs away from WebKit.
declare -a clean_env
keep_vars=(
  HOME USER LOGNAME PATH PWD SHELL TERM LANG LANGUAGE LC_ALL LC_CTYPE COLORTERM
  DISPLAY WAYLAND_DISPLAY XDG_RUNTIME_DIR XDG_SESSION_TYPE DBUS_SESSION_BUS_ADDRESS XAUTHORITY
  CARGO_HOME RUSTUP_HOME RUSTUP_TOOLCHAIN NPM_CONFIG_CACHE npm_config_cache
  SSL_CERT_FILE SSL_CERT_DIR HTTP_PROXY HTTPS_PROXY NO_PROXY http_proxy https_proxy no_proxy
)

for name in "${keep_vars[@]}"; do
  if [[ -n "${!name-}" ]]; then
    clean_env+=("${name}=${!name}")
  fi
done

xdg_data_dirs="${XDG_DATA_DIRS:-/usr/local/share:/usr/share}"
xdg_data_dirs="$(sanitize_colon_list "${xdg_data_dirs}")"
if [[ -z "${xdg_data_dirs}" ]]; then
  xdg_data_dirs="/usr/local/share:/usr/share"
fi
clean_env+=("XDG_DATA_DIRS=${xdg_data_dirs}")

if [[ -n "${XDG_CONFIG_DIRS:-}" ]]; then
  xdg_config_dirs="$(sanitize_colon_list "${XDG_CONFIG_DIRS}")"
  if [[ -n "${xdg_config_dirs}" ]]; then
    clean_env+=("XDG_CONFIG_DIRS=${xdg_config_dirs}")
  fi
fi

exec env -i "${clean_env[@]}" node "${tauri_cli}" "$@"
