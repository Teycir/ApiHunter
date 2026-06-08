#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
desktop_dir="$(cd "${script_dir}/.." && pwd)"
# Try release first, fall back to debug
release_binary="${desktop_dir}/src-tauri/target/release/apihunter-desktop"
debug_binary="${desktop_dir}/src-tauri/target/debug/apihunter-desktop"
if [[ -x "${release_binary}" ]]; then
  binary="${release_binary}"
else
  binary="${debug_binary}"
fi

if [[ ! -x "${binary}" ]]; then
  echo "ApiHunter Desktop binary not found at: ${binary}" >&2
  echo "Build it first with: cd ${desktop_dir} && npm run tauri build" >&2
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

exec env -i "${clean_env[@]}" "${binary}" "$@"
