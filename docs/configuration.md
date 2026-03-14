---
author: teycir ben soltane
email: teycir@pxdmail.net
website: teycirbensoltane.tn
last_updated: 2026-03-14
tags: [configuration, cli, settings, parameters]
category: Configuration Guide
---

# Configuration Reference

All fields live in `Config` (populated by `clap`).  
Durations are in milliseconds unless noted.

| Field | Type | Default | Description |
|---|---|---|---|
| `urls` | `Vec<String>` | required | Target URLs |
| `concurrency` | `usize` | `20` | Max parallel tasks |
| `max_endpoints` | `usize` | `500` | Hard cap on discovered endpoints |
| `min_severity` | `Severity` | `Low` | Drop findings below this |
| `output_path` | `Option<PathBuf>` | `None` (stdout) | NDJSON output file |
| `quiet` | `bool` | `false` | Suppress non-error output |
| `summary` | `bool` | `false` | One-line summary after scan |
| `timeout_secs` | `u64` | `30` | Per-request HTTP timeout |
| `retries` | `u32` | `3` | Retry budget per request |
| `politeness.delay_ms` | `u64` | `100` | Delay between requests to same host |
| `proxy` | `Option<String>` | `None` | Proxy URL |
| `accept_invalid_certs` | `bool` | `false` | Skip TLS verification |
