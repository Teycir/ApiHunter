# ApiHunter Roadmap

> Last updated: June 9 2026 · Current release: **v0.7.0**

This document tracks what has shipped, what is actively being built, and where the project is headed. Items are grouped by theme and ordered within each phase by priority.

---

## Release History (Shipped)

| Version | Date | Theme |
|---------|------|-------|
| v0.1.0 | Mar 2026 | Initial CLI scanner + core engine |
| v0.2.0 | Mar 2026 | Desktop app (Tauri + React), multi-target input, live progress |
| v0.3.0 | Apr 2026 | Advanced transport/auth controls, preset profiles, response-diff deep mode, gRPC/Protobuf scanner |
| v0.3.1 | Apr 2026 | Version metadata wiring, desktop release chip |
| v0.3.2 | Apr 2026 | Load past scan from export directory (`--load-scan`) |
| v0.4.0 | Apr 2026 | Triage mode with risk scoring, `--fail-on` severity CI flag, bulk promote-to-deep-scan |
| v0.5.0 | Apr 2026 | Discovery configuration (`DiscoveryConfig`), Enrich workflow, scan presets, `threat_intel` module |
| v0.6.0 | Apr 2026 | Enrich → Deep-Scan promote flow, `--promote-to` CLI flag, Enrich desktop panel, 25-test enrich suite |
| v0.7.0 | Apr 2026 | Glass UI redesign, scan persistence (last-scan store), results analytics dashboard, scan cancel button, log auto-scroll, formatted elapsed time |

---

## Phase 7 — Desktop Quality & Code Health *(in progress)*

These are the highest-leverage improvements identified in the May 2026 code review. No new scanner features — purely making what exists solid and maintainable.

### Critical fixes

- [x] **Fix inline style token mismatches** — audited every `style={{}}` prop in JSX; replaced `--color-surface-alt` → `--bg-surface` and all `--color-text-muted` → `--text-muted`.
- [x] **Fix missing `.result-grid` CSS class** — added `.result-grid` as an alias for `.results-layout` in `styles.css`, including all responsive breakpoints.
- [x] **Fix CSV size limit constant** — removed `MAX_CSV_FILE_BITS`; `MAX_CSV_FILE_BYTES = 5 * 1024` is now the single source of truth. UI copy corrected to "5 KiB (5,120 bytes)" everywhere.

### UX wins

- [ ] **Scan cancel button** — once `runFullScan()` fires there is no abort. Add a cancel button that sends a Tauri command to stop the backend runner and resets loading state.
- [x] **Log view auto-scroll** — wired `logViewRef` + `userScrolledRef`; `useEffect` scrolls to bottom on new log lines; `onScroll` opts out when user has scrolled up manually; resets on each new scan.
- [x] **Format elapsed time** — `formatElapsedMs()` helper added; shows "3m 8s" instead of "188818 ms" in Results summary, Loaded Scan panel, and Enrich output.
- [ ] **Loaded scan finding cards** — Critical/High findings for a loaded past scan are currently rendered inside a `log-view` div (a monospace scroll box meant for raw logs). Give them their own styled container matching the live scan results panel.
- [x] **Guard enrichNdjson auto-populate** — `window.confirm()` fires when a second scan completes and the Enrich panel already has custom NDJSON loaded, preventing silent overwrite.

### Code quality

- [ ] **Split App.tsx** — the file is ~2,660 lines. The empty `components/` and `hooks/` directories are ready to use. Extract `ScanForm`, `ResultsPanel`, `EnrichPanel`, `LiveProgress`, and `LoadedScan` into their own files.
- [ ] **Custom hooks** — consolidate the 30+ `useState` calls in `App()` into `useScanConfig()`, `useScanResults()`, and `useEnrich()` hooks.
- [x] **`applyPreset()` deep branch** — wrapped the implicit fallthrough in an explicit `if (mode === "deep") { … }` block so future insertions cannot silently break preset logic.
- [x] **`saveSingleExport()` lookup map** — replaced three chained ternary expressions with a typed `EXPORT_MAP` constant; function signature tightened to `"json" | ExportKey`.
- [ ] **Extract `SeverityHeatmap` component** — the IIFE pattern `{summary.findingsTotal > 0 && (() => { ... })()}` is hard to read and untestable. Make it a named component.
- [ ] **Add React `ErrorBoundary` around Results** — a rendering error in any of the 10 result sub-cards currently crashes the whole app.

### State persistence

- [x] **Persist last scan to Tauri store** — all scan state is ephemeral. Closing and reopening the app wipes results. Persist the last scan summary and exports to `localStorage` or a Tauri app-data store.
- [ ] **Scan history ring-buffer** — store the last 5 scan summaries so users can compare runs without re-scanning.

---

## Phase 8 — Scanner Depth

Expanding detection coverage across existing scanners with higher-signal checks.

- [ ] **Mass assignment active fuzzing improvements** — schema-aware field injection using OpenAPI specs when available; per-operation baseline replay to reduce false positives.
- [ ] **JWT: algorithm confusion probes** — `RS256→HS256` confusion and `none` alg bypass via active checks.
- [ ] **OAuth/OIDC: PKCE downgrade detection** — identify flows that accept auth codes without PKCE even when the spec requires it.
- [ ] **CORS: credentialed wildcard origin bypass** — probe for origins that reflect `Access-Control-Allow-Origin: <attacker>` with `Access-Control-Allow-Credentials: true`.
- [ ] **Rate limit: distributed bypass probes** — send bursts with rotated IPs (via proxy pool) to detect per-IP-only limiters.
- [ ] **WebSocket: auth boundary drift** — check whether WS upgrade strips auth headers that the HTTP endpoint enforced.
- [ ] **API versioning: schema-aware auth-context fuzzing** — replay requests with swapped auth tokens across discovered version paths.

---

## Phase 9 — Desktop Features

New capability in the desktop UI, building on the stable code base from Phase 7.

- [ ] **Finding detail drawer** — clicking a check name in "Top Checks" slides open a side panel listing all URLs for that check, their evidence, and a one-click "copy as curl" command.
- [ ] **Per-target timing in live progress** — show "started 4s ago / done in 2.1s" on each target progress card so slow or WAF-blocked targets are visible in real time.
- [ ] **Enrich host card expand/collapse** — when 50+ hosts are returned the list is overwhelming. Collapse to host + score + severity badge by default; expand on click to show ports, CVEs, and signals.
- [ ] **Keyboard shortcuts** — `Cmd/Ctrl+Enter` to run scan, `Escape` to cancel, `Cmd/Ctrl+Shift+E` to open enrich panel.
- [ ] **Dark/light theme toggle** — the new dark theme is great; add a toggle persisted to Tauri store for users who prefer light mode.
- [ ] **Notification on scan complete** — native OS desktop notification when a long-running scan finishes (Tauri notification API).

---

## Phase 10 — Integrations & Pipeline

Making ApiHunter fit naturally into existing security workflows and CI/CD pipelines.

- [ ] **GitHub Actions native action** — publish `apihunter/scan-action` to the Actions marketplace. Inputs: target URLs, preset, fail-on severity. Outputs: findings count per severity, SARIF upload.
- [ ] **SARIF v2.1 enrichment** — populate `help.markdown` and `properties.tags` in SARIF output so GitHub Code Scanning surfaces check descriptions inline in PR diffs.
- [ ] **Burp Suite extension** — export findings as a Burp-importable XML issue list so analysts can continue investigation in Burp.
- [ ] **Defect Dojo integration** — push findings to a configured Defect Dojo endpoint via `--push-to-dojo` flag (product ID + API key from env).
- [ ] **Slack / webhook alerts** — `--notify-webhook <URL>` sends a JSON payload on scan complete with severity summary and worst-target link.
- [ ] **Collection import: OpenAPI 3.1** — extend `--collection` to parse OpenAPI 3.1 `requestBody` schemas for richer per-operation fuzzing context.

---

## Phase 11 — Performance & Scale

- [ ] **Adaptive rate limiting per host** — detect rate-limit responses (429, `Retry-After`) and back off per host rather than aborting.
- [ ] **Streaming NDJSON output** — write findings to the NDJSON file as they arrive rather than buffering to memory, enabling real-time `tail -f` monitoring of large scans.
- [ ] **Result virtualization in desktop** — for scans returning 500+ findings the target progress grid and result cards are slow to render. Use a virtual list (e.g. `react-window`) so the UI stays smooth at any scale.
- [ ] **Log view virtualization** — same fix for the log view; at 250 entries DOM updates become noticeable.
- [ ] **Parallel Enrich + scan** — allow Enrich to run concurrently with a Mass Sweep scan instead of requiring sequential phases.

---

## Phase 12 — Reporting

- [ ] **HTML report export** — self-contained single-file HTML report with severity breakdown, per-target cards, top checks table, and heatmap. Suitable for sharing with stakeholders who do not have the desktop app.
- [ ] **PDF report export** — same content as the HTML report, generated via headless Chromium / `wkhtmltopdf` from Tauri backend.
- [ ] **Executive summary mode** — one-page PDF: risk score, critical/high count, top 3 recommended remediations, scan metadata. Designed for non-technical audiences.
- [ ] **Trend report** — compare two saved scans side-by-side: new findings, resolved findings, severity changes per target.

---

## Backlog (Unscheduled)

Ideas that are validated in principle but not yet assigned to a phase.

- **Browser extension** — intercept requests in Chrome/Firefox, add discovered URLs directly to the target list without copy-pasting.
- **LLM-assisted remediation hints** — for each finding, call an LLM to generate a one-paragraph "how to fix this" tailored to the detected stack (detected from response headers).
- **Authenticated session recording** — record a browser login flow (via Playwright) and replay auth cookies/tokens automatically across all scan targets.
- **Team / multi-user mode** — shared scan history and findings triage in a self-hosted backend, with per-user assignment of findings.
- **Mobile companion app** — read-only view of scan summaries and findings on iOS/Android via a lightweight API served by the desktop app.

---

## Contributing

See [`CONTRIBUTING.md`](../CONTRIBUTING.md) for the development workflow. If you want to pick up an item from this roadmap, open an issue first to avoid duplicate work. Items marked with **[ ]** are open for contribution — preference given to Phase 7 fixes since they unblock everything downstream.