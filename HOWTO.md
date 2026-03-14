# How-to guide

Practical recipes for common tasks.

---

## Run a basic scan

```bash
./target/release/api-scanner --urls https://target.example.com
```

Findings are written as NDJSON to **stdout**; diagnostics to **stderr**.

---

## Save results to a file

```bash
./target/release/api-scanner --urls https://target.example.com --output report.ndjson
```

When `--output` is set, the report is written to the file. Stdout still prints
unless `--quiet` is used.

---

## Stream findings as NDJSON

```bash
./target/release/api-scanner --urls https://target.example.com --format ndjson --stream
```

---

## SARIF output (GitHub Code Scanning)

```bash
./target/release/api-scanner --urls https://target.example.com --format sarif --output results.sarif
```

---

## Baseline diff mode

```bash
./target/release/api-scanner --urls https://target.example.com --baseline last.ndjson --format ndjson
```

---

## Filter by severity

```bash
./target/release/api-scanner --urls https://target.example.com --min-severity high
```

Accepted values (low → critical): `low` `medium` `high` `critical`

---

## Scan multiple targets

```bash
./target/release/api-scanner \
  --urls https://app.example.com \
  --urls https://api.example.com \
  --concurrency 40
```

---

## Use in CI

```bash
./target/release/api-scanner --urls "$TARGET" --quiet --min-severity medium
EXIT=$?

if (( EXIT & 1 )); then echo "Findings detected"; fi
if (( EXIT & 2 )); then echo "Scanner errors occurred"; fi
```

---

## Scan through a proxy (Burp, mitmproxy, etc.)

```bash
./target/release/api-scanner \
  --urls https://target.example.com \
  --proxy http://127.0.0.1:8080 \
  --danger-accept-invalid-certs
```

---

## Enable active checks (opt-in)

```bash
./target/release/api-scanner --urls https://target.example.com --active-checks
```

---

## Auth helpers and session cookies

```bash
./target/release/api-scanner --urls https://target.example.com --auth-bearer "$TOKEN"
./target/release/api-scanner --urls https://target.example.com --auth-basic "user:pass"
./target/release/api-scanner --urls https://target.example.com --session-file session.json
```

`session.json` format:

```json
{
  "hosts": {
    "example.com": {
      "session": "abc123"
    }
  }
}
```

---

## Write a custom scanner

1. Create `src/scanner/my_check.rs`
2. Implement the `Scanner` trait:

```rust
use async_trait::async_trait;
use crate::{
    config::Config,
    error::CapturedError,
    http_client::HttpClient,
    reports::Finding,
    scanner::Scanner,
};

pub struct MyCheck;

#[async_trait]
impl Scanner for MyCheck {
    async fn scan(
        &self,
        url: &str,
        client: &HttpClient,
        _config: &Config,
    ) -> (Vec<Finding>, Vec<CapturedError>) {
        // your logic here
        (vec![], vec![])
    }
}
```

3. Register it in `src/runner.rs` inside the scanner list.

---

## Run tests

```bash
# Unit + integration (requires network for wiremock-based tests)
cargo test

# Only unit tests
cargo test --lib

# With logs visible
RUST_LOG=debug cargo test -- --nocapture
```

---

## Configuration reference

See [`docs/configuration.md`](docs/configuration.md) for every config field,
its type, default, and environment variable override.
