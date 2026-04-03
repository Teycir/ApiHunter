<!-- donation:eth:start -->
<div align="center">

## Support Development

If this project helps your work, support ongoing maintenance and new features.

**ETH Donation Wallet**  
`0x11282eE5726B3370c8B480e321b3B2aA13686582`

<a href="https://etherscan.io/address/0x11282eE5726B3370c8B480e321b3B2aA13686582">
  <img src="publiceth.svg" alt="Ethereum donation QR code" width="220" />
</a>

_Scan the QR code or copy the wallet address above._

</div>
<!-- donation:eth:end -->


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

Async, modular API security scanner for API baseline testing and regression detection.  
Combines discovery with targeted checks (CORS/CSP/GraphQL/OpenAPI/JWT/API Security) using adaptive concurrency and CI-ready outputs (NDJSON/SARIF).

Use cases: offense for red-team/API pentest discovery and exploit validation, and defense for CI/CD regression gating, continuous API hardening, and early misconfiguration detection.

## Naming

- Project/repository: `ApiHunter`
- Cargo package: `apihunter`
- Library crate: `api_scanner`
- CLI binary: `apihunter` (default for `cargo run`)

## GitHub Metadata (Recommended)

Set these in the GitHub repository settings for discoverability:

- **Description**: `Async API security scanner for CORS/CSP/GraphQL/JWT/OpenAPI and active API posture checks.`
- **Website**: `https://github.com/Teycir/ApiHunter`
- **Topics**: `rust`, `security`, `api-security`, `scanner`, `graphql`, `cors`, `csp`, `jwt`, `openapi`, `sarif`, `ndjson`

## Repository Flow

```mermaid
flowchart LR
    A[CLI apihunter] --> B[main.rs]
    D[Input Sources] --> E[Pre-filter + Discovery]
    B --> C[HttpClient + Config]
    E --> F[runner.rs]
    C --> F

    F --> G1[Passive scanners]
    F --> G2[Active scanners]

    I[template-tool] --> H[CVE templates]
    H --> G2

    G1 --> J[Findings]
    G2 --> J
    J --> K[Reporter]
    K --> L[Auto Reports]
    K --> M[CI/CD Controls]
```

## Why ApiHunter?

### Core Advantages

- **API-First Architecture**: Purpose-built for REST/GraphQL APIs, not adapted from web app scanners
- **Intelligent False Positive Reduction**: 
  - SPA catch-all detection with canary probing
  - Context-aware secret validation (frontend vs backend)
  - Body content validation and referer checking
  - Response fingerprinting to skip duplicate findings
- **Production-Safe by Design**:
  - Adaptive concurrency (AIMD) that backs off on errors
  - Per-host rate limiting with configurable delays
  - Politeness controls (retries, timeouts, WAF evasion)
  - Dry-run mode for active checks
- **Stealth & Evasion**:
  - Runtime User-Agent rotation from curated pool (assets/user_agents.txt)
  - Randomized request delays with jitter
  - Per-host delay enforcement (avoids burst patterns)
  - Retry logic with exponential backoff
  - Custom header injection for blending with legitimate traffic
  - Adaptive timing based on server responses
  - No hardcoded scanner fingerprints in default mode
- **CI/CD Native**:
  - Baseline diffing (only report new findings)
  - Streaming NDJSON output for real-time monitoring
  - SARIF 2.1.0 for GitHub/GitLab Code Scanning
  - Exit code bitmask for pipeline control
  - Severity-based filtering and failure thresholds
- **Performance at Scale**:
  - Rust async runtime (tokio) with zero-cost abstractions
  - Concurrent scanning with semaphore-bounded parallelism
  - Per-host HTTP client pools to avoid connection bottlenecks
  - Efficient memory usage (no GC pauses)
- **Comprehensive Auth Support**:
  - JSON-based auth flows with cookie/header extraction
  - Dual-identity IDOR/BOLA testing
  - Session file import (Excalibur integration)
  - Bearer, Basic, and custom header auth
  - Automatic unauth client for privilege escalation checks

## Scanner Modules

ApiHunter includes 13 built-in scanner modules. See [docs/scanners.md](docs/scanners.md) for detailed detection logic.

| Scanner | Type | What It Detects |
|---------|------|----------------|
| **CORS** | Passive | Wildcard origins, reflected origins with credentials, null origin acceptance, regex bypass vulnerabilities (suffix/prefix attacks), missing Vary: Origin, unsafe preflight methods |
| **CSP** | Passive | Missing Content-Security-Policy, unsafe-inline/unsafe-eval directives, wildcard sources, bypassable CDN hosts (JSONP gadgets), missing frame-ancestors |
| **GraphQL** | Passive | Introspection enabled, sensitive schema fields (user/password/token types), field suggestions (schema leakage), query batching, alias amplification (DoS), GraphiQL/Playground exposure |
| **JWT** | Passive | alg=none tokens, weak HS256 secrets (wordlist-based), missing/excessive expiry, sensitive claims in payload, algorithm confusion vulnerabilities |
| **OpenAPI** | Passive | Missing security schemes, operations without auth requirements, file upload endpoints, deprecated operations still present, unsecured sensitive endpoints |
| **API Versioning** | Passive | Version header disclosure, concurrent legacy/new API versions, deprecation headers, and response drift across benign query/version variants (plus deep mode via `--response-diff-deep`) |
| **gRPC/Protobuf** | Passive + Active | gRPC transport/content-type signals, protobuf surface hints, and optional reflection/health probe signals |
| **API Security** | Passive + Active | Missing security headers (X-Content-Type-Options, X-Frame-Options), server version disclosure, unauthenticated access to sensitive paths, HTTP method enumeration, debug endpoints, secret exposure patterns, active IDOR/BOLA checks (body + selected header comparison), blind SSRF callback probes, and gateway/bypass probe signals |
| **Mass Assignment** | Active | Reflected sensitive fields (is_admin, role, permissions), persisted state changes, privilege escalation via field injection |
| **OAuth/OIDC** | Active | Redirect URI validation bypass, missing state parameter, PKCE support issues (missing S256, plain allowed), implicit flow enabled, password grant enabled |
| **Rate Limit** | Active | Missing rate limiting (burst probes), missing Retry-After headers, IP header spoofing bypass (X-Forwarded-For) |
| **WebSocket** | Active | WebSocket upgrade acceptance on common paths, missing origin validation, unauthenticated WebSocket connections |
| **CVE Templates** | Active | Template-driven CVE detection from `assets/cve_templates/*.toml` (168 templates currently), baseline vs bypass differential matching |

**Passive scanners** run by default and analyze responses without sending crafted requests.  
**Active scanners/checks** require `--active-checks` and send potentially invasive probes (IDOR/BOLA, mutation, bypass tests).  
IDOR/BOLA lives under the `API Security` scanner (there is no dedicated `--no-idor` flag; use `--no-api-security` to disable it).

### Module Output & Signal Notes

These notes summarize how findings are emitted and what typically causes noise:

| Module | Finding Prefix / Shape | Common False Positives | Common False Negatives |
|---------|-------------------------|-------------------------|-------------------------|
| CORS | `cors/*` with origin/evidence fields | Reflection on non-sensitive routes | Origin checks applied only on authenticated routes |
| CSP | `csp/*` with directive evidence | Legacy CSP applied intentionally during migration | CSP delivered only on production CDN edge path |
| GraphQL | `graphql/*` with endpoint + capability signal | Public playground intended for internal/testing tenants | Schema controls enabled only after auth |
| JWT | `jwt/*` with token claim/header evidence | Test/demo tokens in synthetic responses | Token never appears in scanned responses |
| OpenAPI | `openapi/*` with operation/security context | Spec intentionally includes deprecated but blocked endpoints | Spec unavailable or split across private docs |
| API Versioning | `api_versioning/*` + `response_diff/*` | Multiple supported versions during controlled migrations | Versioned paths not discoverable from current seed set |
| gRPC/Protobuf | `grpc_protobuf/*` with transport/reflection evidence | gRPC-like metadata on edge proxies without exposed RPC surface | gRPC endpoints behind separate host/path not reached from seed set |
| API Security | `api_security/*` with header/path/method evidence | Debug/test endpoints intentionally exposed in non-prod | Controls enforced behind auth/session context |
| Mass Assignment | `mass_assignment/*` with reflected/persisted deltas | Echo behavior that does not persist backend state | Mutations rejected by hidden validation rules |
| OAuth/OIDC | `oauth/*` with redirect/metadata evidence | Non-production IdP config with relaxed policies | Dynamic policy enforcement not visible in metadata |
| Rate Limit | `rate_limit/*` with burst/429 behavior | Global traffic shaping masks app-level limiter behavior | Long-window limiters not triggered by short probe window |
| WebSocket | `websocket/*` with upgrade/origin checks | Public WS endpoints intentionally anonymous | Auth required via handshake headers not provided in probe |
| CVE Templates | `cve/<id>/<check>` with template evidence | Fingerprint collision on generic endpoints | Vulnerable path/context not reached from seed URLs |

For check-by-check detail and remediation guidance, see [docs/scanners.md](docs/scanners.md) and [docs/findings.md](docs/findings.md).
The scanner docs now include a source-aligned [Module Check Catalog](docs/scanners.md#module-check-catalog) and [False-Positive Expectation Model](docs/scanners.md#false-positive-expectation-model).

## Features

### Passive Security Analysis
- **CORS Misconfiguration Detection**:
  - Dynamic origin generation based on target domain
  - Regex bypass testing (suffix/prefix attacks)
  - Credential-aware severity scoring
  - Wildcard and null origin detection
- **CSP Policy Analysis**:
  - Missing/weak Content Security Policy detection
  - Unsafe inline/eval directives
  - Wildcard source detection
  - Policy bypass patterns
- **GraphQL Security**:
  - Introspection query detection
  - Sensitive type/field name analysis
  - Query batching support detection
  - Alias amplification (DoS) probing
  - Active mutation fuzzing (`--active-checks`, supports `--dry-run`)
  - GraphiQL/Playground exposure
- **JWT Token Analysis**:
  - Algorithm confusion (alg=none, HS256→RS256)
  - Weak secret detection (curated wordlist)
  - Long-lived token detection (missing/excessive exp)
  - Sensitive claim exposure
  - Token extraction from headers and cookies
- **OpenAPI/Swagger Analysis**:
  - Security scheme validation
  - File upload endpoint detection
  - Deprecated operation flagging
  - Missing security definitions
  - Spec caching for performance
- **gRPC/Protobuf Coverage**:
  - gRPC response metadata/content-type detection
  - Protobuf surface hint detection from endpoint metadata/path shape
  - Optional reflection/health active probe signals on known gRPC paths
- **Secret Exposure Detection**:
  - AWS keys (AKIA*, secret keys)
  - Google API keys (AIza*)
  - GitHub tokens (ghp_*, github_pat_*)
  - Slack tokens (xox*)
  - Stripe keys (sk_live_*, pk_live_*)
  - Database URLs, private keys, bearer tokens
  - Context-aware validation (reduces false positives)
- **API Security Checks**:
  - HTTP method enumeration
  - Debug endpoint detection
  - Directory listing exposure
  - Security.txt presence
  - Response header analysis (HSTS, X-Frame-Options, etc.)
  - Error message disclosure

### Active Security Testing (--active-checks)
- **API Security IDOR/BOLA Checks** (3-tier approach):
  - Unauthenticated access testing
  - Response comparison via body fingerprints plus stable header snapshots
  - ID enumeration (±2 range walk)
  - Cross-user authorization bypass (dual-identity)
  - Blind SSRF callback probing via callback-style query params (`APIHUNTER_OAST_BASE`, supports `--dry-run`)
  - Gateway fingerprint and bypass probing (`api_security/gateway-*`)
- **Mass Assignment Vulnerabilities**:
  - Reflected sensitive field injection
  - Persisted state change detection
  - Baseline→Mutate→Confirm verification
  - Privilege escalation via field injection
- **OAuth/OIDC Security**:
  - Redirect URI validation bypass
  - State parameter handling
  - PKCE support detection
  - Metadata configuration hardening
  - Implicit flow and password grant detection
- **Rate Limiting**:
  - Burst request probing
  - Missing rate limit detection
  - Retry-After header validation
  - IP header spoofing bypass tests
- **WebSocket Security**:
  - Upgrade acceptance on common paths
  - Origin validation testing
  - Missing authentication checks
- **CVE Template Engine**:
  - TOML-based template catalog
  - Nuclei YAML import support
  - Baseline vs bypass differential matching
  - Host+template deduplication
  - Loader quality gates skip invalid/unsafe request templates (for example unresolved request placeholders)
  - Segment-aware context matching reduces broad path-substring over-triggering
  - Current local catalog: 168 templates (includes curated hardened checks such as CVE-2022-22947, CVE-2021-29442, CVE-2021-29441, CVE-2020-13945, CVE-2021-45232, CVE-2022-24288)

### Discovery & Enumeration
- **Endpoint Discovery**:
  - robots.txt parsing
  - sitemap.xml parsing
  - OpenAPI/Swagger spec import
  - HAR file import (Excalibur integration)
  - Postman/Insomnia collection import (`--collection`)
  - JavaScript endpoint extraction
  - Same-host filtering
- **URL Accessibility Pre-filtering**:
  - Fast pre-check to skip dead endpoints
  - Configurable timeout
  - Optional bypass with --no-filter

### Performance & Reliability
- **Adaptive Concurrency (AIMD)**:
  - Automatic rate adjustment based on errors
  - Additive increase (every 5s)
  - Multiplicative decrease on 429/503/timeouts
- **Stealth & WAF Evasion**:
  - User-Agent rotation from runtime pool (assets/user_agents.txt with 100+ real UAs)
  - Embedded fallback UAs if file unavailable
  - Random delay jitter to avoid detection patterns
  - Per-host timing enforcement (not global)
  - Retry logic with exponential backoff
  - Custom header injection (X-Forwarded-For, Referer, etc.)
  - Adaptive timing based on 429/503 responses
  - Politeness mode for cooperative testing
  - No scanner fingerprints in User-Agent or headers by default
- **Resource Management**:
  - Semaphore-bounded parallelism
  - Per-host HTTP client pools
  - Connection reuse and pooling
  - Configurable timeouts and retries
- **Error Handling**:
  - Panic recovery via JoinSet
  - Captured errors reported separately
  - Graceful degradation on scanner failures

### Output & Reporting
- **Multiple Output Formats**:
  - Pretty JSON (human-readable)
  - NDJSON (streaming, parseable)
  - SARIF 2.1.0 (GitHub/GitLab Code Scanning)
- **Baseline Diffing**:
  - Generate baseline snapshots
  - Compare scans to report only new findings
  - Perfect for regression testing
- **Auto-Save Reports** (enabled by default, disable with `--no-auto-report`):
  - Saved to ~/Documents/ApiHunterReports/<timestamp>/
  - findings.json (structured findings)
  - summary.md (markdown report)
  - scan.log (execution log)
- **Real-Time Streaming**:
  - Stream findings as they're discovered
  - NDJSON format for live parsing
  - Progress tracking
- **Severity Filtering**:
  - Filter by minimum severity (info/low/medium/high/critical)
  - Fail-on threshold for CI/CD
  - Exit code bitmask (0x01 findings, 0x02 errors)

### Integration & Extensibility
- **Pluggable Scanner Architecture**:
  - Implement Scanner trait to add modules
  - Async-first design
  - Independent scanner execution
  - Panic isolation per scanner
- **TOML-Based Extensibility**:
  - CVE template catalog in assets/cve_templates/*.toml
  - No code changes needed to add new checks
  - Template-driven vulnerability detection
  - Community-shareable template format
- **Nuclei Template Import**:
  - template-tool binary for YAML → TOML conversion
  - Automatic matcher translation (status, word, regex, dsl)
  - Safe preflight request-chain extraction
  - Preserves detection logic from upstream templates
- **Dual Extension Model**:
  - **Code-based**: Write Rust scanners implementing Scanner trait for complex logic
  - **Template-based**: Write TOML templates for signature-based checks (CVEs, misconfigs)
  - Best of both worlds: performance + flexibility
- **Complementary Tools**:
  - Excalibur browser extension (HAR capture)
  - BurpAPIsecuritysuite (manual testing)
  - Workflow: Capture → Automate → Deep test

### Configuration & Control
- **Flexible Input**:
  - File-based URL lists
  - stdin (pipe from other tools)
  - HAR file import
  - Postman/Insomnia collection import
  - OpenAPI spec import
- **Granular Scanner Control**:
  - Enable/disable individual scanners
  - Active vs passive mode
  - Dry-run for active checks
  - Per-scanner configuration
- **Network Configuration**:
  - HTTP/HTTPS proxy support
  - TLS certificate validation control
  - Custom headers and cookies
  - Configurable timeouts and retries
- **Scan Profiles**:
  - quickscan.sh (fast, low-impact)
  - deepscan.sh (comprehensive, active checks)
  - inaccessiblescan.sh (re-check previously inaccessible targets with slower settings)
  - baselinescan.sh (generate baseline)
  - diffscan.sh (compare against baseline)
  - authscan.sh (authenticated scanning)
  - sarifscan.sh (CI/CD integration)
  - scan-and-report.sh (run scan + print latest report path)
  - split-by-host.sh (split targets by host and optionally fan out scans)

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

**ApiHunter:** API-first design, SPA detection, baseline diffing, 3-tier IDOR/BOLA, context-aware secrets, AIMD concurrency, **stealth/WAF evasion (UA rotation, jitter, adaptive timing)**, **dual extensibility (TOML templates + Rust modules)**  
**Nuclei:** Broader CVE coverage, YAML templates only, basic evasion  
**ZAP/Burp:** Manual testing, proxy workflows, GUI-based extensions, limited stealth  
**ffuf:** Pure fuzzing, content discovery, limited extensibility, basic evasion

## Quick Start

```bash
cargo build --release

# Scan URLs from a file (newline-delimited)
./target/release/apihunter --urls ./targets/cve-regression-real-public.txt --format ndjson --output ./results.ndjson

# Or scan URLs from stdin
cat ./targets/cve-regression-real-public.txt | ./target/release/apihunter --stdin --min-severity medium
```

### Desktop Quick Start (Tauri + React)

ApiHunter also ships a desktop app in `apps/desktop`.

```bash
cd apps/desktop
npm install
npm run tauri dev
```

Desktop scan input supports:
- Manual multi-target entry (one URL per line or comma-separated)
- CSV import via `Load CSV`
- Guided scan presets: `Quick Passive`, `Balanced (Recommended)`, and `Deep Active`
- Hard limit: up to 100 targets per run (deduped + validated as absolute `http/https` URLs)
- Scope controls: discovery on/off, accessibility filtering + timeout, max endpoints per site
- API versioning controls: optional deep response-diff probing toggle
- Advanced controls: proxy, headers, cookies, bearer/basic auth, TLS invalid-cert toggle
- Blind SSRF callback correlation input (`OAST callback base`) for active checks
- Performance controls: per-host clients, adaptive concurrency, WAF evasion with custom user-agent pool
- Full scanner toggle coverage including `API Versioning` and `gRPC/Protobuf`
- Parallel-run progress cards with per-target completion/findings snapshots
- Export UX tuned for large runs: size labels + `Save All Reports` + per-run filenames

If you want a release desktop binary:

```bash
cd apps/desktop
npm run tauri build
./src-tauri/target/release/apihunter-desktop
```

Install a clickable Linux app icon/launcher:

```bash
cd apps/desktop
npm run desktop:install-icon
```

Note: desktop dev startup now uses built frontend assets directly and does not require a separate `localhost:1420` server.

See [HOWTO.md](HOWTO.md) for detailed usage, [docs/lab-setup.md](docs/lab-setup.md) for Vulhub-based CVE validation labs, and [docs/](docs/) for internals.

### Example NDJSON Finding

```json
{
  "url": "https://api.example.com/graphql",
  "check": "graphql/introspection-enabled",
  "title": "GraphQL introspection is enabled",
  "severity": "MEDIUM",
  "detail": "Introspection query returned schema metadata from a public endpoint.",
  "evidence": "POST /graphql -> HTTP 200 with __schema fields in response body",
  "scanner": "graphql",
  "timestamp": "2026-03-19T14:02:11.824Z"
}
```

## Architecture

```
main.rs  ──► cli.rs (args) ──► config.rs (Config)
                                     │
                               runner.rs (orchestration)
                              ┌──────┴────────────────────────────┐
                    discovery/               scanner/
                    ├─ robots.rs             ├─ cors.rs
                    ├─ sitemap.rs            ├─ csp.rs
                    ├─ swagger.rs            ├─ jwt.rs
                    ├─ js.rs                 ├─ graphql.rs
                    ├─ headers.rs            ├─ openapi.rs
                    └─ common_paths.rs       ├─ api_security.rs
                                             ├─ api_versioning.rs
                                             ├─ grpc_protobuf.rs
                                             ├─ mass_assignment.rs
                                             ├─ oauth_oidc.rs
                              http_client.rs ├─ rate_limit.rs
                              auth.rs        ├─ cve_templates.rs
                              waf.rs         └─ websocket.rs
                              reports.rs
                              error.rs
```

**Flow:** CLI args → Config → Runner orchestrates Discovery + Scanners → HTTP Client (with Auth/WAF) → Reports

## Template Tooling

ApiHunter supports **dual extensibility**: add checks via **TOML templates** (no code) or **Rust modules** (full control).

### TOML Template Format
Create custom checks in `assets/cve_templates/*.toml`:
```toml
id = "custom-api-check"
name = "Custom API Vulnerability"
severity = "high"

[[requests]]
method = "GET"
path = "/api/vulnerable"

[[requests.matchers]]
type = "status"
values = [200]

[[requests.matchers]]
type = "word"
part = "body"
words = ["sensitive_data", "exposed"]
```

### Import Nuclei Templates
Convert existing Nuclei YAML templates:
```bash
cargo run --bin template-tool -- import-nuclei \
  --input tests/fixtures/upstream_nuclei/CVE-2022-24288.yaml \
  --output assets/cve_templates/cve-2022-24288.toml
```

### Add Custom Rust Scanners
Implement the `Scanner` trait for complex logic:
```rust
#[async_trait]
impl Scanner for MyCustomScanner {
    async fn scan(
        &self,
        url: &str,
        client: &HttpClient,
        config: &Config,
    ) -> (Vec<Finding>, Vec<CapturedError>) {
        // Your custom scanning logic
    }
}
```

See [HOWTO.md](HOWTO.md#import-a-nuclei-cve-template-into-apihunter-toml) and [docs/scanners.md](docs/scanners.md) for details.

## Scan Scripts

`ScanScripts/` contains convenience wrappers for common scan profiles:

- **quickscan.sh** - Fast, low-impact scan (concurrency: 10, max-endpoints: 20, timeout: 5s, retries: 0, delay: 50ms)
- **deepscan.sh** - Comprehensive scan with active checks (adaptive concurrency, per-host clients, unlimited endpoints, retries: 3, timeout: 20s, delay: 200ms)
- **defaultscan.sh** - Run with CLI defaults (no preset flags)
- **baselinescan.sh** - Generate baseline NDJSON for diffing
- **diffscan.sh** - Compare against baseline and report only new findings
- **authscan.sh** - Authenticated scan with auth flows (requires `--auth-flow`, enables active checks, WAF evasion, retries: 2, timeout: 15s, delay: 150ms)
- **sarifscan.sh** - Output SARIF format for CI/CD integration
- **inaccessiblescan.sh** - Re-scan previously inaccessible URLs with conservative retry/timeouts
- **scan-and-report.sh** - Run scan and print latest auto-saved report location
- **split-by-host.sh** - Split URL list into per-host files and optionally scan them in parallel

### Usage Examples

```bash
# Quick scan from file
./ScanScripts/quickscan.sh targets/cve-regression-real-public.txt

# Deep scan from stdin
cat targets/cve-regression-real-public.txt | ./ScanScripts/deepscan.sh --stdin

# Generate baseline
./ScanScripts/baselinescan.sh targets/cve-regression-real-public.txt

# Compare against baseline
./ScanScripts/diffscan.sh targets/cve-regression-real-public.txt baseline.ndjson

# Authenticated scan
./ScanScripts/authscan.sh targets/cve-regression-real-public.txt --auth-flow auth.json

# SARIF output for GitHub Code Scanning
./ScanScripts/sarifscan.sh targets/cve-regression-real-public.txt

# Split by host and scan in parallel
./ScanScripts/split-by-host.sh targets/cve-regression-real-public.txt --scan-cmd ./ScanScripts/quickscan.sh --jobs 4
```

All wrapper scripts except `split-by-host.sh` support `--stdin` and trailing ApiHunter flags.

## Testing Strategy

ApiHunter testing is split by intent:

- **Unit tests** (`tests/*_scanner.rs`, parser/config tests): scanner logic and edge cases.
- **Integration tests** (`tests/integration_runner.rs`, startup/CLI behavior): orchestration and runtime wiring.
- **Fixture regression tests** (`tests/cve_templates_real_data.rs`, `tests/cve_templates_upstream_parity.rs`): replay real payloads and compare against pinned upstream templates.
- **Mock-server tests** (multiple scanner suites): deterministic behavior checks without relying on internet targets.
- **Live-target checks**: optional/manual only (not part of default `cargo test`).

See the dedicated [Testing Guide](docs/testing.md) for the full test matrix and coverage map.

Run focused suites:

```bash
cargo test --test cors_scanner
cargo test --test graphql_scanner
cargo test --test cve_templates_runtime_ext
cargo test --test integration_runner
```

Run full validation:

```bash
cargo test
```

Run real-data integration gate (fixtures + live ignored suites):

```bash
# Fixture-backed real payload regression suites
cargo test --test cve_templates_real_data --test cve_templates_upstream_parity --test cve_templates_runtime_ext

# Manual live internet integration suites (ignored by default)
cargo test --test live_vulnerable_apis --test live_real_world_targets -- --ignored
```

Live suites use default target inventories:
- `targets/vuln-api-regression-real-public.txt`
- `targets/real-world-integration-public.txt`

You can override with:
- `APIHUNTER_LIVE_VULN_TARGET_FILE` or `APIHUNTER_LIVE_VULN_TARGETS`
- `APIHUNTER_LIVE_REAL_TARGET_FILE` or `APIHUNTER_LIVE_REAL_TARGETS`

## Documentation

Complete documentation is available in `docs/`. Start with:

- [Documentation Index](docs/INDEX.md)
- [Desktop App Guide](docs/desktop.md)
- [Architecture](docs/architecture.md)
- [Configuration](docs/configuration.md)
- [Auth Flow](docs/auth-flow.md)
- [Testing Guide](docs/testing.md)
- [Operations Runbook](docs/operations.md)
- [Scanners](docs/scanners.md)
- [Findings & Remediation](docs/findings.md)
- [Security Policy](SECURITY.md)
- [HOWTO](HOWTO.md)

## Roadmap

**Completed:** WebSocket/Mass-Assignment/OAuth/Rate-Limit/CVE scanners, expanded Nuclei importer (regex/dsl + safe preflight chains), Docker image  
**Next:** Expand CVE templates, stealth hardening (remove scanner markers, randomize probes), broader matcher/operator parity for advanced Nuclei expressions

## Installation

### CLI Installation

Requires Rust stable (tested on 1.76+).

```bash
git clone https://github.com/Teycir/ApiHunter
cd ApiHunter
cargo build --release
```

### Prebuilt Release Artifacts

Tagged releases (`v*`) publish prebuilt `apihunter` binaries for:

- Linux (`x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu`)
- macOS (`x86_64-apple-darwin`)
- Windows (`x86_64-pc-windows-msvc`)

Each release also publishes supply-chain artifacts:

- SHA256 checksum files (`*.sha256`)
- Sigstore keyless signature materials (`*.sig`, `*.pem`, `*.sigstore.json`)
- SPDX JSON SBOM (`apihunter-release-assets-sbom.spdx.json`)
- GitHub artifact attestations (provenance and SBOM attestation metadata)

Download from [GitHub Releases](https://github.com/Teycir/ApiHunter/releases).

### Desktop Installation (Tauri + React)

Desktop app source lives in `apps/desktop`.

Build and run a production desktop binary:

```bash
cd apps/desktop
npm install
npm run tauri build
./src-tauri/target/release/apihunter-desktop
```

For development mode:

```bash
cd apps/desktop
npm run tauri dev
```

Install a clickable Linux launcher icon:

```bash
cd apps/desktop
npm run desktop:install-icon
```

Desktop features (brief):
- Multi-target scans (up to 100 targets) with manual input + CSV import
- Guided setup presets for quick, balanced, and deep active scan profiles
- Live progress UI with per-target status cards
- Full scan profile controls (discovery/filtering, retries/timeouts, scanner toggles)
- API versioning deep response-diff toggle in desktop full-scan profile
- OAST callback base control for blind SSRF active-check correlation
- Advanced runtime controls (proxy/auth headers/cookies, TLS toggle, WAF/adaptive/per-host options)
- One-click export for JSON, NDJSON, and SARIF reports

### Docker

```bash
docker build -t apihunter:local .
docker run --rm apihunter:local --help
```

Run a scan from files in your current directory:

```bash
docker run --rm -v "$PWD:/work" apihunter:local \
  --urls /work/targets/cve-regression-real-public.txt \
  --format ndjson \
  --output /work/results.ndjson
```

## CLI Reference

| Flag | Default | Description |
|---|---|---|
| `--urls` | required* | Path to newline-delimited URL file |
| `--stdin` | off | Read newline-delimited URLs from stdin |
| `--har` | off | Import likely API request URLs from HAR (`log.entries[].request.url`) |
| `--collection` | off | Import likely API request URLs from Postman/Insomnia collection export JSON |
| `--output` | stdout | Write results to a file instead of stdout |
| `--format` | `pretty` | Output format: `pretty`, `ndjson`, or `sarif` |
| `--stream` | off | Stream NDJSON findings as they arrive |
| `--baseline` | none | Baseline NDJSON for diff-only findings |
| `--quiet` | off | Suppress non-error stdout output |
| `--summary` | off | Print summary even in quiet mode |
| `--no-auto-report` | off | Skip writing local auto reports under `~/Documents/ApiHunterReports` |
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
| `--unauth-strip-headers` | none | Extra header names to strip for unauth probes |
| `--session-file` | none | Load/save cookies from Excalibur session JSON (`{"hosts": {...}}`) |
| `--proxy` | none | HTTP/HTTPS proxy URL |
| `--danger-accept-invalid-certs` | off | Skip TLS certificate validation |
| `--active-checks` | off | Enable active (potentially invasive) probes |
| `--dry-run` | off | Dry-run active checks (report intended probes without sending mutation requests) |
| `--response-diff-deep` | off | Enable deeper response-diff variant probes in API versioning checks |
| `--per-host-clients` | off | Use per-host HTTP client pools |
| `--adaptive-concurrency` | off | Adaptive concurrency (AIMD) |
| `--no-cors` | off | Disable the CORS scanner |
| `--no-csp` | off | Disable the CSP scanner |
| `--no-graphql` | off | Disable the GraphQL scanner |
| `--no-api-security` | off | Disable the API security scanner |
| `--no-jwt` | off | Disable the JWT scanner |
| `--no-openapi` | off | Disable the OpenAPI scanner |
| `--no-api-versioning` | off | Disable the API versioning scanner |
| `--no-grpc-protobuf` | off | Disable the gRPC/Protobuf scanner |
| `--no-mass-assignment` | off | Disable the Mass Assignment scanner (active checks) |
| `--no-oauth-oidc` | off | Disable the OAuth/OIDC scanner (active checks) |
| `--no-rate-limit` | off | Disable the Rate Limit scanner (active checks) |
| `--no-cve-templates` | off | Disable the CVE template scanner (active checks) |
| `--no-websocket` | off | Disable the WebSocket scanner (active checks) |

*You must provide exactly one of `--urls`, `--stdin`, `--har`, or `--collection`.

## Exit Codes

| Code | Meaning |
|---|---|
| `0` | No findings at/above `--fail-on` threshold and no errors |
| `1` | One or more findings at/above `--fail-on` threshold |
| `2` | One or more scanners captured errors |
| `3` | Both findings and errors |

## Security & Legal Guardrails

- `--proxy` does **not** disable TLS verification on its own. Certificate checks remain enabled unless `--danger-accept-invalid-certs` is explicitly set.
- `--danger-accept-invalid-certs` is intended for controlled lab/debug use only. ApiHunter emits an explicit runtime warning when this flag is enabled.
- `--waf-evasion` and active probes may trigger IDS/WAF alerts. Run only with explicit written authorization and within agreed test windows.
- For CI or production-adjacent checks, prefer passive mode first, then scope active checks to approved targets.

## Related Projects

ApiHunter is part of a complementary security testing toolkit:

- **[Excalibur](https://github.com/Teycir/Excalibur)** - Browser extension for capturing API traffic and exporting HAR files with session cookies. Use with ApiHunter via `--har` and `--session-file` flags.
- **[BurpAPIsecuritysuite](https://github.com/Teycir/BurpAPIsecuritysuite)** - Burp Suite extension for interactive API security testing. Complements ApiHunter's automated scanning with manual testing workflows.

**Workflow:** Capture traffic with Excalibur → Automated baseline with ApiHunter → Deep manual testing with BurpAPIsecuritysuite

## About

**Author:** Teycir Ben Soltane  
**Email:** teycir@pxdmail.net  
**Website:** [teycirbensoltane.tn](https://teycirbensoltane.tn)

## FAQ

**Q: Why ApiHunter vs Nuclei/ZAP/Burp?**  
A: API-first design, SPA detection, baseline diffing, 3-tier IDOR, context-aware secrets. Complementary to Nuclei (CVE coverage) and ZAP/Burp (manual testing).

**Q: Production-safe?**  
A: Yes. Use `--delay-ms` and lower `--concurrency`. Try `quickscan.sh`.

**Q: Authenticated scans?**  
A: `--auth-bearer`, `--auth-basic`, or `--auth-flow`. For IDOR: `--auth-flow-b`.

**Q: Speed comparison (1000 endpoints)?**  
Depends on endpoint latency, retries, target behavior, and enabled checks. Use `--concurrency`, `--delay-ms`, and `--active-checks` to tune throughput vs impact.

**Q: Slow scan?**  
Increase `--concurrency` (default: 20), reduce `--delay-ms` (default: 150ms), enable `--adaptive-concurrency`.

**Q: Output formats?**  
`pretty` (default), `ndjson` (streaming), `sarif` (CI integration).

**Q: CI/CD integration?**  
```bash
./target/release/apihunter --urls targets/cve-regression-real-public.txt --fail-on medium --format sarif --output results.sarif
```

**Q: Baseline diffing?**  
```bash
./target/release/apihunter --urls targets/cve-regression-real-public.txt --format ndjson --output baseline.ndjson
./target/release/apihunter --urls targets/cve-regression-real-public.txt --baseline baseline.ndjson --format ndjson
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
`RUST_LOG=debug ./target/release/apihunter --urls targets/cve-regression-real-public.txt`

**Q: Adaptive concurrency?**  
AIMD: increases by 1 every 5s, halves on errors (429/503/timeouts). Enable with `--adaptive-concurrency`.

**Q: Disable scanners?**  
`--no-cors`, `--no-csp`, `--no-graphql`, `--no-api-security`, `--no-jwt`, `--no-openapi`, `--no-api-versioning`, `--no-mass-assignment`, `--no-oauth-oidc`, `--no-rate-limit`, `--no-cve-templates`, `--no-websocket`.

**Q: Is ApiHunter stealthy?**  
A: Yes. Features: UA rotation from 100+ real browsers (assets/user_agents.txt), randomized delays with jitter, per-host rate limiting, adaptive backoff on 429/503, no scanner fingerprints in headers, exponential retry logic, custom header injection. Enable with `--waf-evasion`.

**Q: How does WAF evasion work?**  
A: Automatically rotates User-Agents from curated pool, adds random jitter to delays, enforces per-host timing (not global bursts), backs off exponentially on rate limits, and allows custom header injection to blend with legitimate traffic. No "scanner" strings in default headers.

See [CONTRIBUTING.md](CONTRIBUTING.md) for development guidelines.

## License

[MIT](LICENSE)
