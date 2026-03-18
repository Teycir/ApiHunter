# How-to guide

Practical recipes for common tasks.

---

## Run a basic scan

Note: `--urls` expects a file path. For a single URL, use `--stdin`:

```bash
printf "https://target.example.com\n" | ./target/release/api-scanner --stdin
```

Findings are written to **stdout** (default `pretty`; use `--format ndjson` for NDJSON);
diagnostics to **stderr**.

---

## Scan scripts

Helper scripts live in `ScanScripts/` and accept either a URL file or `--stdin`.

```bash
./ScanScripts/defaultscan.sh ./targets/targets.txt
cat ./targets/targets.txt | ./ScanScripts/defaultscan.sh --stdin
```

```bash
./ScanScripts/quickscan.sh ./targets/targets.txt
./ScanScripts/deepscan.sh ./targets/targets.txt
```

```bash
./ScanScripts/baselinescan.sh ./targets/targets.txt
./ScanScripts/diffscan.sh ./targets/targets.txt baseline.ndjson
```

```bash
./ScanScripts/inaccessiblescan.sh ./targets/inaccessible.txt
./ScanScripts/authscan.sh ./targets/targets.txt --auth-flow ./flows/auth.json
```

```bash
./ScanScripts/sarifscan.sh ./targets/targets.txt
./ScanScripts/scan-and-report.sh ./targets/targets.txt
```

```bash
./ScanScripts/split-by-host.sh ./targets/targets.txt --out-dir split-targets
./ScanScripts/split-by-host.sh ./targets/targets.txt --scan-cmd ./ScanScripts/quickscan.sh --jobs 4
```

---

## Save results to a file

```bash
printf "https://target.example.com\n" | ./target/release/api-scanner --stdin --output report.ndjson
```

When `--output` is set, the report is written to the file. Stdout still prints
unless `--quiet` is used.

---

## Stream findings as NDJSON

```bash
printf "https://target.example.com\n" | ./target/release/api-scanner --stdin --format ndjson --stream
```

---

## SARIF output (GitHub Code Scanning)

```bash
printf "https://target.example.com\n" | ./target/release/api-scanner --stdin --format sarif --output results.sarif
```

---

## Baseline diff mode

```bash
printf "https://target.example.com\n" | ./target/release/api-scanner --stdin --baseline last.ndjson --format ndjson
```

---

## Filter by severity

```bash
printf "https://target.example.com\n" | ./target/release/api-scanner --stdin --min-severity high
```

Accepted values (low → critical): `low` `medium` `high` `critical`

---

## Scan multiple targets

```bash
cat <<'EOF' > targets.txt
https://app.example.com
https://api.example.com
EOF

./target/release/api-scanner --urls ./targets.txt --concurrency 40
```

---

## Import endpoints from HAR

```bash
./target/release/api-scanner --har ./session.har
./target/release/api-scanner --har ./session.har --har-api-only
```

HAR import reads `log.entries[].request.url` and uses those URLs as scan seeds.
`--har-api-only` focuses the seed list on likely API/business endpoints and excludes static/CDN noise.

---

## Use in CI

```bash
printf "%s\n" "$TARGET" | ./target/release/api-scanner --stdin --quiet --min-severity medium
EXIT=$?

if (( EXIT & 1 )); then echo "Findings detected"; fi
if (( EXIT & 2 )); then echo "Scanner errors occurred"; fi
```

---

## Scan through a proxy (Burp, mitmproxy, etc.)

```bash
printf "https://target.example.com\n" | ./target/release/api-scanner \
  --stdin \
  --proxy http://127.0.0.1:8080 \
  --danger-accept-invalid-certs
```

---

## Enable active checks (opt-in)

```bash
printf "https://target.example.com\n" | ./target/release/api-scanner --stdin --active-checks
```

---

## Auth helpers and session cookies

```bash
printf "https://target.example.com\n" | ./target/release/api-scanner --stdin --auth-bearer "$TOKEN"
printf "https://target.example.com\n" | ./target/release/api-scanner --stdin --auth-basic "user:pass"
printf "https://target.example.com\n" | ./target/release/api-scanner --stdin --session-file session.json
printf "https://target.example.com\n" | ./target/release/api-scanner --stdin --cookies-json cookies.json
printf "https://target.example.com\n" | ./target/release/api-scanner --stdin --session-file cookies.json --session-file-format excalibur
```

`--session-file-format` supports: `auto` (default), `native`, `excalibur`.
`--cookies-json` is shorthand for `--session-file <FILE> --session-file-format excalibur`.

Native `session.json` format:

```json
{
  "hosts": {
    "example.com": {
      "session": "abc123"
    }
  }
}
```

Excalibur `cookies.json` format:

```json
{
  "cookies": {
    ".example.com": {
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
---

## Advanced Examples

### Run with active checks (intrusive probes)

```bash
printf "https://staging.example.com\n" | ./target/release/api-scanner \
  --stdin \
  --active-checks \
  --concurrency 10
```

Use only on staging or with explicit production team approval. Active checks may:
- Generate high request volume
- Trigger WAF/IDS alerts  
- Be detected as attack traffic

---

### Parse results with jq

Count findings by severity:
```bash
cat results.ndjson | jq -r 'select(.type != "meta") | .severity' | sort | uniq -c
```

Extract critical findings only:
```bash
cat results.ndjson | jq 'select(.severity == "CRITICAL")'
```

List unique checks:
```bash
cat results.ndjson | jq -r '.check' | sort -u
```

---

### Scan with custom headers and bearer token

```bash
printf "https://api.example.com\n" | ./target/release/api-scanner \
  --stdin \
  --auth-bearer "eyJhbGciOiJIUzI1NiIs..." \
  --headers "X-Request-ID:scan-001" \
  --format ndjson
```

---

### Comparative scans (baseline diffing)

Run baseline on clean version:
```bash
printf "https://api.example.com\n" | ./target/release/api-scanner \
  --stdin \
  --format ndjson \
  --output baseline.ndjson
```

Scan after changes and report only new/changed findings:
```bash
printf "https://api.example.com\n" | ./target/release/api-scanner \
  --stdin \
  --baseline baseline.ndjson \
  --format ndjson \
  --output new-findings.ndjson
```

---

### Upload SARIF to GitHub Code Scanning

```bash
# Generate SARIF report
printf "https://github.com/my-org/my-repo\n" | ./target/release/api-scanner \
  --stdin \
  --format sarif \
  --output results.sarif

# Upload to GitHub (requires gh CLI)
gh code-scanning upload-sarif results.sarif \
  --repository my-org/my-repo
```

---

## Troubleshooting

### High error rate / timeouts

**Problem:** Many endpoints fail with timeout errors.

**Solution:**
- Increase `--timeout-secs` (default 8)
- Decrease `--concurrency` (default 20)
- Add `--delay-ms` to slow down per-host requests (default 150)

```bash
./target/release/api-scanner \
  --urls ./targets.txt \
  --timeout-secs 60 \
  --concurrency 5 \
  --delay-ms 500
```

---

### WAF blocking requests

**Problem:** Scanner gets 403/429 errors, WAF blocks requests.

**Solution:** Enable WAF evasion, rotate user agents, add delays:
Start conservatively (lower concurrency, higher delay) to avoid triggering rate limits.

```bash
printf "https://target.example.com\n" | ./target/release/api-scanner \
  --stdin \
  --waf-evasion \
  --delay-ms 500 \
  --retries 5
```

---

### Scanner panics or crashes

**Problem:** Specific endpoint causes scanner to panic.

**Solution:**
- Check the error output for the failing URL
- Run with `RUST_LOG=debug` for more detail
- Report with reproduction steps to the project

```bash
printf "https://problematic-url.com\n" | RUST_LOG=debug ./target/release/api-scanner \
  --stdin \
  2>&1 | tee debug.log
```

---

## Interpreting Results

See [`docs/findings.md`](docs/findings.md) for detailed guidance on:
- Severity level meanings
- Common finding types and remediations
- Output formats (NDJSON, SARIF)
- Reducing false positives
