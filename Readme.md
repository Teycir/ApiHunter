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

## Comparison with Other Tools

| Feature | ApiHunter | Nuclei | ZAP | Burp Suite | ffuf |
|---------|-----------|--------|-----|------------|------|
| **Language** | Rust | Go | Java | Java | Go |
| **Performance** | ⚡⚡⚡ Async, adaptive concurrency | ⚡⚡ Fast parallel | ⚡ Moderate | ⚡ Moderate | ⚡⚡⚡ Very fast |
| **API-First Design** | ✅ Built for APIs | ❌ General web | ⚠️ Hybrid | ⚠️ Hybrid | ❌ Fuzzing focus |
| **False Positive Filtering** | ✅ SPA detection, body validation, referer checks | ⚠️ Template-dependent | ⚠️ Many FPs | ✅ Good | N/A |
| **CORS/CSP Analysis** | ✅ Deep policy parsing | ⚠️ Basic templates | ✅ Good | ✅ Good | ❌ |
| **GraphQL Introspection** | ✅ Schema exposure + sensitive field checks | ⚠️ Basic detection | ⚠️ Limited | ✅ Via extensions | ❌ |
| **OpenAPI/Swagger** | ✅ Security scheme analysis | ❌ | ✅ Import only | ✅ Import + scan | ❌ |
| **JWT Analysis** | ✅ alg=none, weak secrets, expiry | ⚠️ Via templates | ⚠️ Limited | ✅ Via extensions | ❌ |
| **IDOR/BOLA Detection** | ✅ 3-tier (unauth/range/cross-user) | ⚠️ Manual templates | ⚠️ Limited | ✅ Manual testing | ❌ |
| **Secret Detection** | ✅ Context-aware (frontend vs backend) | ⚠️ Regex-based | ⚠️ Basic | ⚠️ Basic | ❌ |
| **Active Checks** | ✅ Opt-in (IDOR, mass-assignment, rate-limit) | ✅ Template-based | ✅ Active scan | ✅ Active scan | ✅ Fuzzing |
| **WAF Evasion** | ✅ UA rotation, delays, retries | ⚠️ Basic | ⚠️ Limited | ✅ Good | ⚠️ Basic |
| **CI/CD Integration** | ✅ NDJSON, SARIF, exit codes | ✅ JSON, SARIF | ⚠️ XML reports | ⚠️ XML/JSON | ✅ JSON |
| **Baseline Diffing** | ✅ Built-in | ❌ External tools | ❌ | ❌ | ❌ |
| **Auth Flows** | ✅ JSON-based pre-scan login | ⚠️ Header injection | ✅ Session mgmt | ✅ Session mgmt | ⚠️ Header injection |
| **Streaming Output** | ✅ Real-time NDJSON | ❌ Batch only | ❌ | ❌ | ✅ |
| **Resource Usage** | 🟢 Low (Rust) | 🟢 Low (Go) | 🟡 High (Java) | 🟡 High (Java) | 🟢 Low (Go) |
| **Learning Curve** | 🟢 Simple CLI | 🟢 Template syntax | 🟡 GUI complexity | 🔴 Steep | 🟢 Simple |
| **Extensibility** | ✅ Rust trait system | ✅ YAML templates | ✅ Add-ons | ✅ Extensions | ⚠️ Limited |
| **License** | MIT (Free) | MIT (Free) | Apache 2.0 (Free) | Commercial | MIT (Free) |
| **Best For** | API security in CI/CD, regression testing, CORS/GraphQL/JWT analysis | General vuln scanning, CVE detection | Full web app pentesting | Manual pentesting, complex workflows | Directory/parameter fuzzing |

### Key Differentiators

**ApiHunter excels at:**
- **API-specific security**: Deep CORS/CSP parsing, GraphQL schema analysis, OpenAPI security validation
- **False positive reduction**: SPA catch-all detection, body content validation, context-aware secret detection
- **CI/CD workflows**: Baseline diffing, streaming output, severity-based exit codes, SARIF support
- **Performance**: Rust async runtime with adaptive concurrency for large-scale scans
- **IDOR/BOLA detection**: 3-tier approach (unauthenticated/ID enumeration/cross-user) with dual-identity support

**When to use Nuclei instead:**
- You need community-maintained CVE templates
- You prefer YAML-based extensibility over code
- You're scanning for known vulnerabilities rather than API misconfigurations

**When to use ZAP/Burp instead:**
- You need interactive manual testing
- You require a full proxy/interceptor workflow
- You're testing complex multi-step authentication flows

**When to use ffuf instead:**
- You need pure fuzzing (directories, parameters, subdomains)
- You're doing content discovery rather than security analysis

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

Requires Rust stable (tested on 1.76+).

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
| `--har` | off | Import likely API request URLs from HAR (`log.entries[].request.url`) |
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
| `--session-file` | none | Load/save cookies from Excalibur session JSON (`{"hosts": {...}}`) |
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

*You must provide exactly one of `--urls`, `--stdin`, or `--har`.

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

## FAQ

### General

**Q: Why another security scanner?**  
A: Most scanners are either general-purpose (Nuclei, ZAP) or focus on manual testing (Burp). ApiHunter is purpose-built for **API security in CI/CD pipelines** with deep analysis of modern API patterns (GraphQL, OpenAPI, JWT) and minimal false positives through context-aware validation.

**Q: Is ApiHunter a replacement for Nuclei/ZAP/Burp?**  
A: No, it's complementary. Use ApiHunter for **automated API baseline scans** in CI/CD, Nuclei for CVE detection, and ZAP/Burp for manual pentesting. See the [comparison table](#comparison-with-other-tools) for details.

**Q: Can I use this in production?**  
A: Yes, but use `--delay-ms` and lower `--concurrency` to avoid overwhelming production systems. The `quickscan.sh` profile is designed for production-safe scanning.

**Q: Does it support authenticated scans?**  
A: Yes. Use `--auth-bearer`, `--auth-basic`, or `--auth-flow` (JSON-based login flow). For IDOR detection, provide `--auth-flow-b` for a second identity.

### Performance

**Q: How fast is it compared to other tools?**  
A: On a 1000-endpoint scan with default settings:
- ApiHunter: ~3-5 minutes (Rust async, adaptive concurrency)
- Nuclei: ~5-8 minutes (Go parallel)
- ZAP: ~15-25 minutes (Java, sequential by default)
- Burp: Manual/interactive (not directly comparable)

**Q: Why is my scan slow?**  
A: Check these settings:
- Increase `--concurrency` (default: 20, try 50-100 for faster scans)
- Reduce `--delay-ms` (default: 150ms, try 50ms for internal networks)
- Use `--max-endpoints` to limit endpoints per site (default: 50)
- Enable `--adaptive-concurrency` for automatic rate adjustment
- Use `--per-host-clients` to avoid connection reuse bottlenecks

**Q: Can I scan multiple targets in parallel?**  
A: Yes, use `ScanScripts/split-by-host.sh` to split your URL list by host, then run multiple scanner instances in parallel with GNU parallel or xargs.

### False Positives

**Q: How does SPA detection work?**  
A: ApiHunter sends requests to 3 random canary paths (`/__canary_*`, `/_canary_*`, `/xyzabc*`). If they all return 200 with HTML, it's a SPA with catch-all routing. Subsequent 200+HTML responses are fingerprinted and skipped if they match the SPA shell.

**Q: Can I disable specific checks?**  
A: Yes, use scanner flags: `--no-cors`, `--no-csp`, `--no-graphql`, `--no-api-security`, `--no-jwt`, `--no-openapi`.

### Output & Integration

**Q: What output formats are supported?**  
A: Three formats:
- `pretty` (default): Pretty-printed JSON
- `ndjson`: Newline-delimited JSON for streaming/parsing
- `sarif`: SARIF 2.1.0 for GitHub Code Scanning, GitLab, etc.

**Q: How do I integrate with CI/CD?**  
A: Use exit codes and severity thresholds:
```bash
# Fail pipeline on MEDIUM+ findings
./api-scanner --urls targets.txt --fail-on medium --format sarif --output results.sarif
if [ $? -eq 1 ] || [ $? -eq 3 ]; then
  echo "Security findings detected!"
  exit 1
fi
```

**Q: What's baseline diffing?**  
A: Generate a baseline scan, then compare future scans to only report **new** findings:
```bash
# Generate baseline
./api-scanner --urls targets.txt --format ndjson --output baseline.ndjson

# Later: scan and diff
./api-scanner --urls targets.txt --baseline baseline.ndjson --format ndjson
# Only outputs findings NOT in baseline
```

**Q: Can I stream results in real-time?**  
A: Yes, use `--stream` with `--format ndjson`:
```bash
./api-scanner --urls targets.txt --format ndjson --stream | jq -r '.title'
```

### Scanners & Checks

**Q: What's the difference between passive and active checks?**  
A: 
- **Passive** (default): Analyze responses without modifying requests (CORS, CSP, secrets, headers)
- **Active** (`--active-checks`): Send crafted requests to test behavior (IDOR, mass-assignment, rate-limiting)

**Q: How should I interpret `Access-Control-Allow-Origin: *` with `Access-Control-Allow-Credentials: true`?**  
A: Browsers block credentialed requests in this configuration, so it is not exploitable with credentials. ApiHunter automatically skips this check and only flags `Access-Control-Allow-Origin: *` without credentials as Low severity. Prioritize origin reflection or regex weaknesses because those can enable credentialed CORS exploitation.
Common test origins (current scanner): `https://<target>`, `https://<target>.evil.com`, `https://evil<target>`, `https://attacker<target>`, and suffix variants like `https://<target>%60.evil.com`.

**Q: How does CORS testing work?**  
A: ApiHunter uses dynamic origin generation based on the target URL:
1. Extracts the domain from the target URL (e.g., `api.company.com` from `https://api.company.com/endpoint`)
2. Tests with multiple origins:
   - `null` origin (file:// context)
   - Generic attacker origin (`https://evil.com`)
   - Target origin matching the URL (`https://api.company.com`)
   - Suffix bypass attempts (`https://api.company.com.evil.com`)
   - Prefix bypass attempts (`https://evilapi.company.com`, `https://attackerapi.company.com`)
3. When origin is reflected (excluding same-origin echoes), tests for regex bypasses:
   - Suffix attacks: `https://api.company.com.evil.com`, `https://api.company.com%60.evil.com`
   - Prefix attacks: `https://evilapi.company.com`, `https://attackerapi.company.com`
4. Only flags High severity when bypass succeeds with `Access-Control-Allow-Credentials: true`

This approach discovers actual whitelisted domains and tests for common regex implementation flaws.

**Q: How does IDOR/BOLA detection work?**  
A: Three-tier approach:
1. **Unauthenticated**: Fetch the URL without credentials — if it returns the same data, auth isn't enforced
2. **ID enumeration**: Walk adjacent IDs (±2) — if multiple return 200, per-object auth may be missing
3. **Cross-user** (requires `--auth-flow-b`): Fetch with a second identity — if both get identical data, BOLA is confirmed

**Q: Does it detect secrets in responses?**  
A: Yes, it scans for:
- AWS keys (AKIA*, secret keys)
- Google API keys (AIza*)
- GitHub tokens (ghp_*)
- Slack tokens (xox*)
- Stripe keys (sk_live_*)
- Bearer tokens, database URLs, private keys
- Generic API keys and secrets (with context-aware validation)

**Q: What GraphQL checks are performed?**  
A: 
- Introspection enabled (schema exposure)
- Sensitive type/field names
- Field-name suggestions leakage
- Query batching support
- Alias amplification probe (DoS signal)
- GraphiQL/Playground exposure

**Q: What OpenAPI/Swagger checks are performed?**  
A: 
- Security scheme analysis (auth requirements)
- File upload endpoints
- Deprecated operations
- Missing security definitions

### Authentication & Sessions

**Q: How do I scan with cookies?**  
A: Three options:
```bash
# Option 1: Direct cookies
./api-scanner --urls targets.txt --cookies "session=abc123,token=xyz"

# Option 2: Excalibur session export JSON (from your HAR folder)
./api-scanner --urls targets.txt --session-file excalibur-session-...-cookies.json

# Option 3: Auth flow (login first)
./api-scanner --urls targets.txt --auth-flow login.json
```

For Excalibur exports, pair both files directly:
```bash
./api-scanner --har session.har --session-file excalibur-session-...-cookies.json
```

Accepted session file shape (only):
```json
{"hosts":{"example.com":{"session":"abc123"}}}
```
ApiHunter accepts only this session JSON schema with `--session-file`.

**Q: What's an auth flow file?**  
A: JSON file defining a pre-scan login sequence:
```json
{
  "steps": [
    {
      "method": "POST",
      "url": "https://api.example.com/login",
      "body": {"username": "test", "password": "pass"},
      "extract_cookies": true,
      "extract_headers": ["Authorization"]
    }
  ]
}
```

**Q: Can I test for IDOR with two different users?**  
A: Yes, provide two auth flows:
```bash
./api-scanner --urls targets.txt \
  --auth-flow user1.json \
  --auth-flow-b user2.json \
  --active-checks
```

### Troubleshooting

**Q: I'm getting "connection refused" errors. Why?**  
A: 
- Target may be down or blocking your IP
- Use `--proxy` if you need to route through a proxy
- Check firewall rules
- Try `--danger-accept-invalid-certs` for self-signed certificates

**Q: Scan is timing out on some URLs. What should I do?**  
A: 
- Increase `--timeout-secs` (default: 8s)
- Increase `--retries` (default: 1)
- Use `--filter-timeout` to skip slow targets during pre-filtering
- Check `--delay-ms` — too low may trigger rate limiting

**Q: How do I scan through a corporate proxy?**  
A: 
```bash
./api-scanner --urls targets.txt --proxy http://proxy.corp.com:8080
```

**Q: Can I ignore TLS certificate errors?**  
A: Yes, but only for testing:
```bash
./api-scanner --urls targets.txt --danger-accept-invalid-certs
```

**Q: How do I enable debug logging?**  
A: Set the `RUST_LOG` environment variable:
```bash
RUST_LOG=debug ./api-scanner --urls targets.txt
# Or for specific modules:
RUST_LOG=api_scanner::scanner::graphql=trace ./api-scanner --urls targets.txt
```

### Advanced Usage

**Q: Can I customize HTTP headers?**  
A: Yes:
```bash
./api-scanner --urls targets.txt \
  --headers "X-API-Key: secret123" \
  --headers "X-Custom: value"
```

**Q: How do I rotate User-Agents for WAF evasion?**  
A: 
```bash
./api-scanner --urls targets.txt \
  --user-agents "Mozilla/5.0...,Chrome/120.0...,Safari/17.0..." \
  --waf-evasion
```

**Q: What's adaptive concurrency?**  
A: AIMD (Additive Increase Multiplicative Decrease) algorithm that automatically adjusts concurrency based on error rates:
- Starts at `--concurrency` value
- Increases by 1 every 5 seconds if no errors
- Halves on errors (429, 503, timeouts)
- Use `--adaptive-concurrency` to enable

**Q: Can I scan only specific scanners?**  
A: Yes, disable unwanted scanners:
```bash
# Only run CORS and GraphQL scanners
./api-scanner --urls targets.txt \
  --no-csp --no-api-security --no-jwt --no-openapi
```

**Q: How do I filter findings by severity?**  
A: Use `--min-severity`:
```bash
# Only show HIGH and CRITICAL
./api-scanner --urls targets.txt --min-severity high
```

**Q: Can I auto-save reports?**  
A: Yes, reports are auto-saved to `~/Documents/ApiHunterReports/<timestamp>/`. Use `ScanScripts/scan-and-report.sh` to automatically print the latest report after scanning.

### Contributing

**Q: How do I add a new scanner?**  
A: Implement the `Scanner` trait:
```rust
#[async_trait]
impl Scanner for MyScanner {
    async fn scan(
        &self,
        url: &str,
        client: &HttpClient,
        config: &Config,
    ) -> (Vec<Finding>, Vec<CapturedError>) {
        // Your logic here
    }
}
```
See [docs/scanners.md](docs/scanners.md) for details.

**Q: How do I report a bug or request a feature?**  
A: Open an issue on GitHub with:
- ApiHunter version (`./api-scanner --version`)
- Command used
- Expected vs actual behavior
- Sample URL (if not sensitive)

**Q: Can I contribute?**  
A: Yes! PRs welcome for:
- New scanners
- False positive fixes
- Performance improvements
- Documentation
- Test coverage

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

[MIT](Licence)
