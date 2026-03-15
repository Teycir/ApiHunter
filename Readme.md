<div align="center">

# 🎯 ApiHunter

<img src="https://readme-typing-svg.demolab.com?font=Fira+Code&size=22&duration=3000&pause=1000&color=F75C7E&center=true&vCenter=true&width=600&lines=Async+Web+Security+Scanner;Rust+Powered+%E2%9A%A1;CORS+%7C+CSP+%7C+GraphQL+%7C+API;Modular+%26+Blazingly+Fast" alt="Typing SVG" />

![Rust](https://img.shields.io/badge/rust-%23000000.svg?style=flat&logo=rust&logoColor=white)
![Security](https://img.shields.io/badge/security-scanner-red?style=flat)
![API](https://img.shields.io/badge/API-testing-blue?style=flat)
![Async](https://img.shields.io/badge/async-tokio-green?style=flat)
![CI](https://github.com/Teycir/ApiHunter/actions/workflows/ci.yml/badge.svg)
![License](https://img.shields.io/badge/license-MIT-blue.svg?style=flat)

</div>

---

An async, modular web security scanner written in Rust.  
Great for quickly baselining API exposure in staging or production-like environments, and for catching regressions after gateway, WAF, or auth changes.  
Innovation: combines discovery + targeted checks (CORS/CSP/GraphQL/OpenAPI/JWT) with fast, adaptive concurrency, producing actionable outputs (NDJSON/SARIF) that slot into CI.  
Benefit: faster feedback loops, fewer false positives, and security findings your teams can triage immediately.

## Features

- ⚡ **Fully async** via `tokio` + `reqwest`
- 🔌 **Pluggable scanner modules** — implement `Scanner` and drop in
- 🛡️ **WAF evasion** — UA rotation, politeness delays, retry logic
- 📊 **NDJSON + SARIF output** for pipelines and CI integration
- 🔒 **Proxy support** and TLS control
- 🚦 **Exit-code bitmask** for scripting (`0x01` findings, `0x02` errors)
- 🧾 **JWT checks** — alg=none, weak HS256 secrets, long-lived tokens
- 📜 **OpenAPI analysis** — security schemes, uploads, deprecated ops

## Use Cases

- ✅ Baseline security checks on internal APIs before release
- 🔄 Regression scans in CI after gateway or WAF changes
- 📋 Inventory scanning for CORS/CSP/GraphQL exposure in staging
- 🎯 Triage and prioritization by severity thresholds

## Quick Start

```bash
cargo build --release

# Scan URLs from a file (newline-delimited)
./target/release/api-scanner --urls ./targets/targets.txt --format ndjson --output ./results.ndjson

# Or scan URLs from stdin
cat ./targets/targets.txt | ./target/release/api-scanner --stdin --min-severity medium
```

See [HOWTO.md](HOWTO.md) for detailed usage and [docs/](docs/) for internals.

## Scan Scripts

Helper scripts live in `ScanScripts/`:

- `ScanScripts/defaultscan.sh` — run with CLI defaults.
- `ScanScripts/deepscan.sh` — deeper scan profile (active checks, retries, unlimited endpoints).
- `ScanScripts/quickscan.sh` — fast, low-impact baseline.
- `ScanScripts/baselinescan.sh` — generate `baseline.ndjson` for diffing.
- `ScanScripts/diffscan.sh` — run against a baseline and output only new findings.
- `ScanScripts/inaccessiblescan.sh` — re-scan previously inaccessible URLs with slower settings.
- `ScanScripts/authscan.sh` — scan using `--auth-flow` (supports IDOR checks).
- `ScanScripts/sarifscan.sh` — produce SARIF by default.
- `ScanScripts/split-by-host.sh` — split URL list per host (optional parallel scans).
- `ScanScripts/scan-and-report.sh` — run a scan and print the latest auto-saved report.

## Documentation

Complete documentation is available in `docs/`. Start with:

- [Documentation Index](docs/INDEX.md)
- [Architecture](docs/architecture.md)
- [Configuration](docs/configuration.md)
- [Scanners](docs/scanners.md)
- [Findings & Remediation](docs/findings.md)
- [HOWTO](HOWTO.md)

## Installation

Requires Rust ≥ 1.76 (stable).

```bash
git clone https://github.com/Teycir/ApiHunter
cd ApiHunter
cargo build --release
```

## CLI Reference

| Flag | Default | Description |
|---|---|---|
| `--urls` | required* | Path to newline-delimited URL file |
| `--stdin` | off | Read newline-delimited URLs from stdin |
| `--output` | stdout | Write results to a file instead of stdout |
| `--format` | `pretty` | Output format: `pretty`, `ndjson`, or `sarif` |
| `--stream` | off | Stream NDJSON findings as they arrive |
| `--baseline` | none | Baseline NDJSON for diff-only findings |
| `--quiet` | off | Suppress non-error stdout output |
| `--summary` | off | Print summary even in quiet mode |
| `--min-severity` | `info` | Filter findings below this level |
| `--fail-on` | `medium` | Exit non-zero at or above this severity |
| `--concurrency` | `20` | Max in-flight requests |
| `--max-endpoints` | `50` | Limit scanned endpoints per site (0 = unlimited) |
| `--delay-ms` | `150` | Minimum delay between requests per host |
| `--retries` | `1` | Retry attempts on transient failure |
| `--timeout-secs` | `8` | Per-request timeout in seconds |
| `--no-filter` | off | Skip pre-filtering of inaccessible URLs |
| `--filter-timeout` | `3` | Timeout for accessibility pre-check (seconds) |
| `--waf-evasion` | off | Enable WAF evasion heuristics |
| `--user-agents` | none | Comma-separated UA list (implies WAF evasion) |
| `--headers` | none | Extra request headers (e.g. `Authorization: Bearer ...`) |
| `--cookies` | none | Comma-separated cookies (e.g. `session=abc,theme=dark`) |
| `--auth-bearer` | none | Add `Authorization: Bearer <token>` |
| `--auth-basic` | none | Add HTTP Basic auth (`user:pass`) |
| `--auth-flow` | none | JSON auth flow file (pre-scan login) |
| `--auth-flow-b` | none | Second auth flow for cross-user IDOR checks |
| `--unauth-strip-headers` | default list | Extra header names to strip for unauth probes |
| `--session-file` | none | Load/save cookies from JSON session file |
| `--proxy` | none | HTTP/HTTPS proxy URL |
| `--danger-accept-invalid-certs` | off | Skip TLS certificate validation |
| `--active-checks` | off | Enable active (potentially invasive) probes |
| `--per-host-clients` | off | Use per-host HTTP client pools |
| `--adaptive-concurrency` | off | Adaptive concurrency (AIMD) |
| `--no-cors` | off | Disable the CORS scanner |
| `--no-csp` | off | Disable the CSP scanner |
| `--no-graphql` | off | Disable the GraphQL scanner |
| `--no-api-security` | off | Disable the API security scanner |
| `--no-jwt` | off | Disable the JWT scanner |
| `--no-openapi` | off | Disable the OpenAPI scanner |

*You must provide exactly one of `--urls` or `--stdin`.

## Exit Codes

| Code | Meaning |
|---|---|
| `0` | Clean — no findings, no errors |
| `1` | One or more findings produced |
| `2` | One or more scanners captured errors |
| `3` | Both findings and errors |

## About

**Author:** teycir ben soltane  
**Email:** teycir@pxdmail.net  
**Website:** teycirbensoltane.tn

## License

[MIT](Licence)
