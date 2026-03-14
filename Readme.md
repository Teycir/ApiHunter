# 🔍 webscan

An async, modular web security scanner written in Rust.  
Detects misconfigurations in CORS, CSP, GraphQL, and API security posture
across a set of target endpoints.

## Features

- ⚡ Fully async via `tokio` + `reqwest`
- 🧩 Pluggable scanner modules (implement `Scanner` and drop in)
- 🛡️ WAF evasion, UA rotation, politeness delays, retry logic
- 📊 NDJSON output — pipe-friendly and CI-ready
- 🔒 Proxy support, TLS control, invalid-cert toggle
- 🚦 Exit-code bitmask for scripting (`0x01` findings, `0x02` errors)

## Quick start

```bash
cargo build --release

./target/release/webscan \
  --urls https://example.com \
  --min-severity medium \
  --output-path results.ndjson
```

See [HOWTO.md](HOWTO.md) for detailed usage and [docs/](docs/) for internals.

## Installation

Requires Rust ≥ 1.76 (stable).

```bash
git clone https://github.com/you/webscan
cd webscan
cargo build --release
```

## CLI reference

| Flag | Default | Description |
|---|---|---|
| `--urls` | required | Comma-separated or repeated target URLs |
| `--concurrency` | `20` | Max parallel scanner tasks |
| `--min-severity` | `low` | Filter findings below this level |
| `--output-path` | stdout | Write NDJSON to file instead of stdout |
| `--quiet` | off | Suppress all non-error output |
| `--summary` | off | Print a one-line summary after scanning |
| `--timeout` | `30` | Per-request timeout in seconds |
| `--retries` | `3` | Retry attempts on transient failure |
| `--proxy` | none | HTTP/HTTPS proxy URL |
| `--accept-invalid-certs` | false | Skip TLS certificate validation |

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Clean — no findings, no errors |
| `1` | One or more findings produced |
| `2` | One or more scanners captured errors |
| `3` | Both findings and errors |

## License

[MIT](LICENSE)
