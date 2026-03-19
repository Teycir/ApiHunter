---
author: teycir ben soltane
email: teycir@pxdmail.net
website: teycirbensoltane.tn
last_updated: 2026-03-19
tags: [configuration, cli, settings, parameters]
category: Configuration Guide
---

# Configuration Reference

All fields live in `Config` (populated by `clap`).  
Durations are in milliseconds unless noted.

| Field | Type | Default | Description |
|---|---|---|---|
| `urls` | `Vec<String>` | required* | Target URLs (newline-delimited file or stdin) |
| `concurrency` | `usize` | `20` | Max parallel tasks |
| `max_endpoints` | `usize` | `0` | Hard cap on discovered endpoints (0 = unlimited) |
| `no_discovery` | `bool` | `false` | Skip endpoint discovery and scan only provided seed URLs |
| `min_severity` | `Severity` | `Info` | Drop findings below this |
| `fail_on` | `Severity` | `Medium` | Exit non-zero at or above this level |
| `output_path` | `Option<PathBuf>` | `None` (stdout) | Report output file |
| `format` | `pretty` | Output format (`pretty`, `ndjson`, `sarif`) |
| `stream` | `bool` | `false` | Stream NDJSON findings as they arrive |
| `baseline` | `Option<PathBuf>` | `None` | Baseline NDJSON file (diff mode) |
| `quiet` | `bool` | `false` | Suppress non-error output |
| `summary` | `bool` | `false` | One-line summary after scan |
| `timeout_secs` | `u64` | `30` | Per-request HTTP timeout |
| `retries` | `u32` | `3` | Retry budget per request |
| `politeness.delay_ms` | `u64` | `100` | Per-host delay between requests |
| `headers` | `Vec<String>` | `[]` | Default request headers (NAME:VALUE) |
| `cookies` | `Vec<String>` | `[]` | Default cookies (NAME=VALUE) |
| `auth_bearer` | `Option<String>` | `None` | Shorthand for `Authorization: Bearer ...` |
| `auth_basic` | `Option<String>` | `None` | Shorthand for HTTP Basic auth |
| `auth_flow` | `Option<PathBuf>` | `None` | JSON auth flow file (see `docs/auth-flow.md`) |
| `auth_flow_b` | `Option<PathBuf>` | `None` | Second auth flow for cross-user IDOR checks |
| `unauth_strip_headers` | `Vec<String>` | default list | Header names stripped for unauthenticated probes |
| `session_file` | `Option<PathBuf>` | `None` | Load/save cookies from Excalibur session JSON (`{"hosts": {...}}`) |
| `proxy` | `Option<String>` | `None` | Proxy URL |
| `danger_accept_invalid_certs` | `bool` | `false` | Skip TLS verification |
| `active_checks` | `bool` | `false` | Enable active (potentially invasive) probes |
| `dry_run` | `bool` | `false` | Dry-run active checks (report intended probes without sending mutation requests) |
| `per_host_clients` | `bool` | `false` | Use per-host HTTP client pools |
| `adaptive_concurrency` | `bool` | `false` | Adaptive concurrency (AIMD) |
| `no_jwt` | `bool` | `false` | Disable JWT scanner |
| `no_openapi` | `bool` | `false` | Disable OpenAPI scanner |
| `no_mass_assignment` | `bool` | `false` | Disable Mass Assignment scanner (active checks) |
| `no_oauth_oidc` | `bool` | `false` | Disable OAuth/OIDC scanner (active checks) |
| `no_rate_limit` | `bool` | `false` | Disable Rate Limit scanner (active checks) |
| `no_cve_templates` | `bool` | `false` | Disable CVE template scanner (active checks) |
| `no_websocket` | `bool` | `false` | Disable WebSocket scanner (active checks) |

*You must provide exactly one of `--urls`, `--stdin`, or `--har`.
HAR parsing is API-focused by default: static/CDN entries are filtered out automatically.
For Excalibur workflows, use `--har <session.har>` with `--session-file <excalibur-session-...-cookies.json>`.

Accepted session file format (JSON, only):

```json
{
  "hosts": {
    "example.com": {
      "session": "abc123"
    }
  }
}
```

This is the only accepted session schema for `--session-file`.
