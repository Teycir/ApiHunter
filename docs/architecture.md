---
author: teycir ben soltane
email: teycir@pxdmail.net
website: teycirbensoltane.tn
last_updated: 2026-03-14
tags: [architecture, design, modules, async-runtime]
category: Technical Documentation
---

# Architecture

## System Overview

```
main.rs
  └─ Config (clap)
       └─ Runner
            ├─ Discovery       → normalise + dedup URLs
            ├─ HttpClient      → politeness / retry / UA / WAF / TLS
            ├─ Scanner trait   → cors | csp | graphql | api_security | jwt
            └─ Reporter        → Pretty / NDJSON (stdout or file)
```

### Key invariants

- **Scanner isolation** — each scanner runs inside a `JoinSet` task;
  panics are caught and converted to `CapturedError`.
- **Back-pressure** — a `Semaphore` with capacity = `concurrency` gates
  all scanner tasks; no unbounded spawning.
- **Determinism** — findings and errors are sorted after aggregation so
  output order is stable across runs.
- **Politeness** — `HttpClient` inserts a configurable delay between
  requests to the same host; respects `delay_ms` from config.

### Data flow

```
URLs
 │  dedupe + canonicalise (Discovery)
 ▼
[endpoint, endpoint, ...]   (capped at max_endpoints)
 │  for each endpoint × scanner
 │  acquire Semaphore permit → spawn task
 ▼
(Vec<Finding>, Vec<CapturedError>)
 │  aggregate → sort → dedup
 ▼
RunResult { id, findings, errors, endpoints_scanned }
 │
 ▼
Reporter::write_run_result()  →  NDJSON line
```
