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

Async, modular web security scanner for API baseline testing and regression detection.  
Combines discovery with targeted checks (CORS/CSP/GraphQL/OpenAPI/JWT/IDOR) using adaptive concurrency and CI-ready outputs (NDJSON/SARIF).

## Features

- ⚡ Async Rust (`tokio` + `reqwest`) with adaptive concurrency
- 🔌 Pluggable scanner modules via trait system
- 🛡️ WAF evasion (UA rotation, delays, retries)
- 📊 NDJSON/SARIF output with baseline diffing
- 🚦 Exit-code bitmask for CI (`0x01` findings, `0x02` errors)
- 🧾 JWT/OpenAPI/GraphQL/CORS/CSP analysis
- 🎯 Active checks: IDOR/BOLA, mass-assignment, OAuth/OIDC, rate-limit, CVE templates

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
| **Active Checks** | ✅ Opt-in (IDOR, mass-assignment, OAuth/OIDC, websocket, rate-limit, CVE templates) | ✅ Template-based | ✅ Active scan | ✅ Active scan | ✅ Fuzzing |
| **WAF Evasion** | ✅ UA rotation, delays, retries, adaptive timing | ⚠️ Basic | ⚠️ Limited | ✅ Good | ⚠️ Basic |
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

**ApiHunter:** API-first design, SPA detection, baseline diffing, 3-tier IDOR/BOLA, context-aware secrets, AIMD concurrency  
**Nuclei:** Broader CVE coverage, YAML templates  
**ZAP/Burp:** Manual testing, proxy workflows  
**ffuf:** Pure fuzzing, content discovery

## Quick Start

```bash
cargo build --release

# Scan URLs from a file (newline-delimited)
./target/release/api-scanner --urls ./targets/targets.txt --format ndjson --output ./results.ndjson

# Or scan URLs from stdin
cat ./targets/targets.txt | ./target/release/api-scanner --stdin --min-severity medium
```

See [HOWTO.md](HOWTO.md) for detailed usage and [docs/](docs/) for internals.

## Template Tooling

Import Nuclei CVE templates:
```bash
cargo run --bin template-tool -- import-nuclei \
  --input tests/fixtures/upstream_nuclei/CVE-2022-24288.yaml \
  --output assets/cve_templates/cve-2022-24288.toml
```
See [HOWTO.md](HOWTO.md#import-a-nuclei-cve-template-into-apihunter-toml) for details.

## Scan Scripts

`ScanScripts/` contains helpers: `quickscan.sh`, `deepscan.sh`, `baselinescan.sh`, `diffscan.sh`, `authscan.sh`, `sarifscan.sh`, `split-by-host.sh`.

## Documentation

Complete documentation is available in `docs/`. Start with:

- [Documentation Index](docs/INDEX.md)
- [Architecture](docs/architecture.md)
- [Configuration](docs/configuration.md)
- [Auth Flow](docs/auth-flow.md)
- [Scanners](docs/scanners.md)
- [Findings & Remediation](docs/findings.md)
- [HOWTO](HOWTO.md)

## Roadmap

**Completed:** WebSocket/Mass-Assignment/OAuth/Rate-Limit/CVE scanners, Nuclei importer, Docker image  
**Next:** Expand CVE templates, stealth hardening (remove scanner markers, randomize probes), multi-step template chains

## Installation

Requires Rust stable (tested on 1.76+).

```bash
git clone https://github.com/Teycir/ApiHunter
cd ApiHunter
cargo build --release
```

### Docker

```bash
docker build -t apihunter:local .
docker run --rm apihunter:local --help
```

Run a scan from files in your current directory:

```bash
docker run --rm -v "$PWD:/work" apihunter:local \
  --urls /work/targets/targets.txt \
  --format ndjson \
  --output /work/results.ndjson
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
| `--no-discovery` | off | Skip endpoint discovery and scan only provided seed URLs |
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
| `--dry-run` | off | Dry-run active checks (report intended probes without sending mutation requests) |
| `--per-host-clients` | off | Use per-host HTTP client pools |
| `--adaptive-concurrency` | off | Adaptive concurrency (AIMD) |
| `--no-cors` | off | Disable the CORS scanner |
| `--no-csp` | off | Disable the CSP scanner |
| `--no-graphql` | off | Disable the GraphQL scanner |
| `--no-api-security` | off | Disable the API security scanner |
| `--no-jwt` | off | Disable the JWT scanner |
| `--no-openapi` | off | Disable the OpenAPI scanner |
| `--no-mass-assignment` | off | Disable the Mass Assignment scanner (active checks) |
| `--no-oauth-oidc` | off | Disable the OAuth/OIDC scanner (active checks) |
| `--no-rate-limit` | off | Disable the Rate Limit scanner (active checks) |
| `--no-cve-templates` | off | Disable the CVE template scanner (active checks) |
| `--no-websocket` | off | Disable the WebSocket scanner (active checks) |

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

**Q: Why ApiHunter vs Nuclei/ZAP/Burp?**  
A: API-first design, SPA detection, baseline diffing, 3-tier IDOR, context-aware secrets. Complementary to Nuclei (CVE coverage) and ZAP/Burp (manual testing).

**Q: Production-safe?**  
A: Yes. Use `--delay-ms` and lower `--concurrency`. Try `quickscan.sh`.

**Q: Authenticated scans?**  
A: `--auth-bearer`, `--auth-basic`, or `--auth-flow`. For IDOR: `--auth-flow-b`.

**Q: Speed comparison (1000 endpoints)?**  
ApiHunter: 3-5min | Nuclei: 5-8min | ZAP: 15-25min

**Q: Slow scan?**  
Increase `--concurrency` (default: 20), reduce `--delay-ms` (default: 150ms), enable `--adaptive-concurrency`.

**Q: Output formats?**  
`pretty` (default), `ndjson` (streaming), `sarif` (CI integration).

**Q: CI/CD integration?**  
```bash
./api-scanner --urls targets.txt --fail-on medium --format sarif --output results.sarif
```

**Q: Baseline diffing?**  
```bash
./api-scanner --urls targets.txt --format ndjson --output baseline.ndjson
./api-scanner --urls targets.txt --baseline baseline.ndjson --format ndjson
```

**Q: Passive vs active checks?**  
Passive (default): analyze responses. Active (`--active-checks`): send crafted requests (IDOR, mass-assignment, OAuth, rate-limit, CVE probes).

**Q: CORS testing?**  
Dynamic origin generation: `null`, `https://evil.com`, `https://<target>.evil.com`, `https://evil<target>`. Tests regex bypasses when reflected.

**Q: IDOR detection?**  
3-tier: (1) unauthenticated fetch, (2) ID enumeration (±2), (3) cross-user (`--auth-flow-b`).

**Q: Secret detection?**  
AWS/Google/GitHub/Slack/Stripe keys, bearer tokens, DB URLs, private keys. Context-aware validation.

**Q: Cookies?**  
`--cookies "session=abc"`, `--session-file excalibur.json`, or `--auth-flow login.json`.

**Q: Proxy?**  
`--proxy http://proxy.corp.com:8080`

**Q: Debug logging?**  
`RUST_LOG=debug ./api-scanner --urls targets.txt`

**Q: Adaptive concurrency?**  
AIMD: increases by 1 every 5s, halves on errors (429/503/timeouts). Enable with `--adaptive-concurrency`.

**Q: Disable scanners?**  
`--no-cors`, `--no-csp`, `--no-graphql`, `--no-api-security`, `--no-jwt`, `--no-openapi`, `--no-mass-assignment`, `--no-oauth-oidc`, `--no-rate-limit`, `--no-cve-templates`, `--no-websocket`.

See [CONTRIBUTING.md](CONTRIBUTING.md) for development guidelines.

## License

[MIT](Licence)
