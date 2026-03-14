# ApiHunter

**Tags:** security, scanner, rust, api, async

An async, modular web security scanner written in Rust.
Detects misconfigurations in CORS, CSP, GraphQL, and API security posture
across a set of target endpoints you own or have explicit permission to test.

## Features

- Fully async via `tokio` + `reqwest`
- Pluggable scanner modules (implement `Scanner` and drop in)
- WAF evasion, UA rotation, politeness delays, retry logic
- NDJSON output for pipelines and CI
- Proxy support and TLS control
- Exit-code bitmask for scripting (`0x01` findings, `0x02` errors)

## Quick start

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

## CLI reference

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

## Exit codes

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
