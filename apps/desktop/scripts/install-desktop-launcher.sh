#!/usr/bin/env bash
set -euo pipefail

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "Desktop launcher install is currently supported on Linux only."
  exit 1
fi

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
desktop_dir="$(cd "${script_dir}/.." && pwd)"
repo_root="$(cd "${desktop_dir}/../.." && pwd)"

launcher_script="${script_dir}/launch-apihunter-desktop.sh"
binary="${desktop_dir}/src-tauri/target/release/apihunter-desktop"
icon_source="${desktop_dir}/src-tauri/icons/icon.png"

if [[ ! -x "${launcher_script}" ]]; then
  echo "Launcher script missing or not executable: ${launcher_script}" >&2
  exit 1
fi

if [[ ! -f "${icon_source}" ]]; then
  echo "Icon file missing: ${icon_source}" >&2
  exit 1
fi

if [[ ! -x "${binary}" ]]; then
  echo "Release binary not found. Building desktop app first..."
  (cd "${desktop_dir}" && npm run tauri build)
fi

if [[ ! -x "${binary}" ]]; then
  echo "Failed to produce desktop binary at: ${binary}" >&2
  exit 1
fi

applications_dir="${HOME}/.local/share/applications"
icons_root="${HOME}/.local/share/icons/hicolor"
pixmaps_dir="${HOME}/.local/share/pixmaps"
desktop_entry_path="${applications_dir}/apihunter-desktop.desktop"
icon_name="apihunter-desktop"
icon_target_pixmaps="${pixmaps_dir}/${icon_name}.png"
desktop_shortcut="${HOME}/Desktop/ApiHunter Desktop.desktop"

mkdir -p "${applications_dir}" "${pixmaps_dir}"

# Install icon in common lookup locations used by desktop launchers.
icon_sizes=(16 24 32 48 64 96 128 256 512)
for size in "${icon_sizes[@]}"; do
  target_dir="${icons_root}/${size}x${size}/apps"
  mkdir -p "${target_dir}"
  convert "${icon_source}" -resize "${size}x${size}" -background none -gravity center -extent "${size}x${size}" "${target_dir}/${icon_name}.png"
done

cp "${icon_source}" "${icon_target_pixmaps}"

if [[ ! -f "${icons_root}/index.theme" ]]; then
  if [[ -f "/usr/share/icons/hicolor/index.theme" ]]; then
    cp "/usr/share/icons/hicolor/index.theme" "${icons_root}/index.theme"
  else
    cat >"${icons_root}/index.theme" <<EOF
[Icon Theme]
Name=Hicolor
Comment=Fallback icon theme
Directories=256x256/apps,512x512/apps

[256x256/apps]
Size=256
Context=Applications
Type=Fixed

[512x512/apps]
Size=512
Context=Applications
Type=Fixed
EOF
  fi
fi

cat >"${desktop_entry_path}" <<EOF
[Desktop Entry]
Type=Application
Name=ApiHunter Desktop
Comment=API security scanner desktop app
Exec=${launcher_script}
Path=${repo_root}
Icon=${icon_name}
Terminal=false
Categories=Development;Security;
StartupNotify=true
EOF

chmod 644 "${desktop_entry_path}"

if [[ -d "${HOME}/Desktop" ]]; then
  cp "${desktop_entry_path}" "${desktop_shortcut}"
  chmod +x "${desktop_shortcut}"
fi

if command -v gtk-update-icon-cache >/dev/null 2>&1; then
  gtk-update-icon-cache -f "${icons_root}" >/dev/null 2>&1 || true
fi

if command -v update-desktop-database >/dev/null 2>&1; then
  update-desktop-database "${applications_dir}" >/dev/null 2>&1 || true
fi

echo "Desktop launcher installed:"
echo "  App menu: ${desktop_entry_path}"
if [[ -d "${HOME}/Desktop" ]]; then
  echo "  Desktop shortcut: ${desktop_shortcut}"
fi
echo
echo "You can now search and open 'ApiHunter Desktop' from your system launcher."
