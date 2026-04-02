---
author: teycir ben soltane
email: teycir@pxdmail.net
website: teycirbensoltane.tn
last_updated: 2026-04-02
tags: [desktop, tauri, react, vite, ui]
category: Desktop App Guide
---

# Desktop App (Tauri + Vite + React)

ApiHunter now includes a desktop app under `apps/desktop`.

## What Exists Now

- Tauri 2 backend (`apps/desktop/src-tauri`) wired to the existing Rust scanner core.
- React + Vite frontend (`apps/desktop/src`) with:
  - branded header icon symbol for quick product recognition,
  - full scan profile form (active checks, dry-run, discovery, concurrency/timeouts/retries),
  - manual multi-target entry (one-per-line or comma-separated),
  - CSV target import,
  - per-scanner toggles,
  - live event/log stream with progress bar and per-target completion cards for parallel runs,
  - findings summary cards and top-check list,
  - export controls for JSON, NDJSON, SARIF with size labels and one-click `Save All Reports`.
- First backend commands:
  - `health_check`
  - `run_quick_scan`
  - `run_full_scan`

`run_quick_scan` intentionally starts in low-impact mode:
- no endpoint discovery,
- passive scanner set,
- active checks disabled.

`run_full_scan` exposes full desktop-configurable scanning and emits live progress events (`scan-event`) to the UI.
It accepts up to 100 targets per run (deduped, validated as `http/https` absolute URLs).

## Prerequisites

- Node.js 20+
- Rust stable (1.76+)
- Platform prerequisites for Tauri 2

Linux (Debian/Ubuntu family) commonly needs system packages like:

```bash
sudo apt update
sudo apt install -y \
  libwebkit2gtk-4.1-dev \
  libgtk-3-dev \
  libayatana-appindicator3-dev \
  librsvg2-dev \
  pkg-config
```

If `cargo check` fails with missing `gobject-2.0` / `webkit2gtk` via `pkg-config`, install the packages above for your distro equivalent.

## Run (Dev)

```bash
cd apps/desktop
npm install
npm run tauri dev
```

Note: `npm run tauri ...` now runs a Linux preflight dependency check first and fails fast with an install command if GTK/WebKit libs are missing.
Note: dev startup now builds and serves the bundled `dist` assets directly (no `localhost:1420` dependency), avoiding “Could not connect to localhost” windows when a separate dev server is not running.

## Install Desktop Icon (Linux)

Create a clickable launcher icon in your app menu (and Desktop shortcut when `~/Desktop` exists):

```bash
cd apps/desktop
npm run desktop:install-icon
```

This command builds the release desktop binary if needed, then installs:
- `~/.local/share/applications/apihunter-desktop.desktop`
- `~/.local/share/icons/hicolor/256x256/apps/apihunter-desktop.png`
- `~/Desktop/ApiHunter Desktop.desktop` (if the Desktop directory exists)

## Frontend Build Check

```bash
cd apps/desktop
npm run build
```

## Current Scope and Next Steps

Current scaffold goal is bootstrap velocity, not full feature parity with CLI.

Recommended next implementation phases:

1. Add cancellable/background scan jobs so UI control is non-blocking.
2. Add richer report explorer (findings table filters, grouping, drill-down).
3. Add auth-flow/session-file UI wiring and secure local credential storage ergonomics.
