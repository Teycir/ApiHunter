<div align="center">

# 🎯 ApiHunter

<img src="https://readme-typing-svg.demolab.com?font=Fira+Code&size=22&duration=3000&pause=1000&color=F75C7E&center=true&vCenter=true&width=600&lines=Async+Web+Security+Scanner;Rust+Powered+%E2%9A%A1;CORS+%7C+CSP+%7C+GraphQL+%7C+API;Modular+%26+Blazingly+Fast" alt="Typing SVG" />

![Rust](https://img.shields.io/badge/rust-%23000000.svg?style=flat&logo=rust&logoColor=white)
![Security](https://img.shields.io/badge/security-scanner-red?style=flat)
![API](https://img.shields.io/badge/API-testing-blue?style=flat)
![Async](https://img.shields.io/badge/async-tokio-green?style=flat)
![License](https://img.shields.io/badge/license-MIT-blue.svg?style=flat)

</div>

---

An async, modular web security scanner written in Rust.  
Detects misconfigurations in CORS, CSP, GraphQL, and API security posture across target endpoints.

## Features

- ⚡ **Fully async** via `tokio` + `reqwest`
- 🔌 **Pluggable scanner modules** — implement `Scanner` and drop in
- 🛡️ **WAF evasion** — UA rotation, politeness delays, retry logic
- 📊 **NDJSON output** for pipelines and CI integration
- 🔒 **Proxy support** and TLS control
- 🚦 **Exit-code bitmask** for scripting (`0x01` findings, `0x02` errors)

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

## Documentation

Complete documentation is available in `docs/`. Start with:

- [Documentation Index](docs/INDEX.md)
- [Architecture](docs/architecture.md)
- [Configuration](docs/configuration.md)
- [Scanners](docs/scanners.md)
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
| `--format` | `pretty` | Output format: `pretty` or `ndjson` |
| `--min-severity` | `info` | Filter findings below this level |
| `--fail-on` | `medium` | Exit non-zero at or above this severity |
| `--concurrency` | `20` | Max in-flight requests |
| `--max-endpoints` | `0` | Limit scanned URLs (0 = unlimited) |
| `--delay-ms` | `100` | Minimum delay between requests per host |
| `--retries` | `3` | Retry attempts on transient failure |
| `--timeout-secs` | `30` | Per-request timeout in seconds |
| `--waf-evasion` | off | Enable WAF evasion heuristics |
| `--user-agents` | none | Comma-separated UA list (implies WAF evasion) |
| `--proxy` | none | HTTP/HTTPS proxy URL |
| `--danger-accept-invalid-certs` | off | Skip TLS certificate validation |
| `--no-cors` | off | Disable the CORS scanner |
| `--no-csp` | off | Disable the CSP scanner |
| `--no-graphql` | off | Disable the GraphQL scanner |
| `--no-api-security` | off | Disable the API security scanner |

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
