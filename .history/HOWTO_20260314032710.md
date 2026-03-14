# How-to guide

Practical recipes for common tasks.

---

## Run a basic scan

```bash
./webscan --urls https://target.example.com
```

Findings are written as NDJSON to **stdout**; diagnostics to **stderr**.

---

## Save results to a file

```bash
./webscan --urls https://target.example.com --output-path report.ndjson
```

When `--output-path` is set, stdout is silent — only the file is written.

---

## Filter by severity

```bash
./webscan --urls https://target.example.com --min-severity high
```

Accepted values (low → critical): `low` `medium` `high` `critical`

---

## Scan multiple targets

```bash
./webscan \
  --urls https://app.example.com \
  --urls https://api.example.com \
  --concurrency 40
```

---

## Use in CI

```bash
./webscan --urls "$TARGET" --quiet --min-severity medium
EXIT=$?

if (( EXIT & 1 )); then echo "Findings detected"; fi
if (( EXIT & 2 )); then echo "Scanner errors occurred"; fi
```

---

## Scan through a proxy (Burp, mitmproxy, etc.)

```bash
./webscan \
  --urls https://target.example.com \
  --proxy http://127.0.0.1:8080 \
  --accept-invalid-certs
```

---

## Write a custom scanner

1. Create `src/scanner/my_check.rs`
2. Implement the `Scanner` trait:

```rust
use async_trait::async_trait;
use crate::{error::CapturedError, http_client::HttpClient, scanner::{Finding, Scanner}};

pub struct MyCheck;

#[async_trait]
impl Scanner for MyCheck {
    async fn scan(
        &self,
        client: &HttpClient,
        endpoint: &str,
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
