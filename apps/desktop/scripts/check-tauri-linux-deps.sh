#!/usr/bin/env bash
set -euo pipefail

if [[ "$(uname -s)" != "Linux" ]]; then
  exit 0
fi

if ! command -v pkg-config >/dev/null 2>&1; then
  echo "[tauri-preflight] Missing 'pkg-config'."
  echo "Install with: sudo apt install -y pkg-config"
  exit 1
fi

required=(
  glib-2.0
  gobject-2.0
  gio-2.0
  gtk+-3.0
  webkit2gtk-4.1
)

missing=()
for dep in "${required[@]}"; do
  if ! pkg-config --exists "$dep"; then
    missing+=("$dep")
  fi
done

if (( ${#missing[@]} > 0 )); then
  echo "[tauri-preflight] Missing Linux system libraries required by Tauri:"
  for dep in "${missing[@]}"; do
    echo "  - $dep"
  done
  echo
  echo "Ubuntu/Debian install command:"
  echo "  sudo apt update && sudo apt install -y libwebkit2gtk-4.1-dev libgtk-3-dev libayatana-appindicator3-dev librsvg2-dev pkg-config"
  exit 1
fi

exit 0
