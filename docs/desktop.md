---
author: teycir ben soltane
email: teycir@pxdmail.net
website: teycirbensoltane.tn
last_updated: 2026-06-09
tags: [desktop, tauri, react, vite, ui]
category: Desktop App Guide
---

# Desktop App (Tauri + Vite + React)

ApiHunter ships a full desktop app under `apps/desktop` (v0.7.0+).

## What Exists Now

- Tauri 2 backend (`apps/desktop/src-tauri`) wired to the existing Rust scanner core.
- React + Vite frontend (`apps/desktop/src`) with a **Premium Glass UI** dark theme (deep blue + electric cyan, glass-morphism panels, JetBrains Mono + Syne typography), featuring:
  - branded header icon and version chip in the Overview panel,
  - **Full Scan** profile form with collapsible subsections (`Safety and Scan Behavior`, `Runtime Limits`, `Scanner toggles` — collapsed by default),
  - manual multi-target entry (one-per-line or comma-separated) and CSV import (300 KiB limit),
  - two guided scan presets: **Quick Passive** and **Deep Active**,
  - advanced transport/auth/performance controls (proxy, headers, cookies, bearer/basic auth, TLS invalid-cert toggle, per-host clients, adaptive concurrency, WAF evasion/user-agent pool),
  - per-scanner toggles with full parity for all 13 modules,
  - live event/log stream with progress bar and per-target completion cards for parallel runs,
  - **Results analytics dashboard**: severity heatmap, worst-target meta-card, scan efficiency metric, summary, findings breakdown, top checks, target ranking, most-highs, scanner coverage, top vulnerable paths, check severity breakdown (top 5), and per-target summary,
  - **Session persistence**: last scan auto-restores on next launch with a `⟳ restored from last session (<timestamp>)` badge,
  - **Enrich Mode** panel: load findings NDJSON (from last scan or file), run threat-intel enrichment, promote hosts scoring above a threshold directly to Full Scan with Deep Active preset applied,
  - **Load Past Scan** panel: load any previous export directory via native file picker,
  - export controls for per-target JSON bundles, NDJSON, SARIF, Insomnia collection, and Insomnia Runner data with size labels and `Save All Reports`.
- Tauri backend commands:
  - `health_check`
  - `run_quick_scan`
  - `run_full_scan`
  - `cancel_scan`
  - `persist_last_scan` / `load_persisted_scan`
  - `save_export` / `load_past_scan` / `read_text_file`
  - `run_enrich`

`run_quick_scan` starts in low-impact mode (no discovery, passive scanners, active checks disabled).

`run_full_scan` exposes full desktop-configurable scanning with live `scan-event` progress streaming. Accepts up to 500 targets per run (deduped, validated `http/https` URLs). Pre-filters inaccessible targets before the full run when filtering is enabled.

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
