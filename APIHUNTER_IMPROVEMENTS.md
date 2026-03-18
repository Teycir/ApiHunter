# ApiHunter — Improvement Recommendations

> Code-based analysis of `github.com/Teycir/ApiHunter`.  
> All recommendations are grounded in the actual codebase reviewed — no speculation.

---

## Current Module Inventory (as of review)

| Layer | Modules |
|---|---|
| **Scanners** | `api_security`, `cors`, `csp`, `graphql`, `jwt`, `openapi` |
| **Discovery** | `common_paths`, `headers`, `js`, `robots`, `sitemap`, `swagger` |
| **Core** | `http_client`, `waf`, `auth`, `config`, `runner`, `reports` |

The `Scanner` trait is already plug-and-play — every recommendation below is a new `impl Scanner` drop-in unless noted otherwise.

---

## 1. CVE Template Module ⚡ Highest Impact

### Why
ApiHunter's stealth layer (UA rotation, `sec-fetch-*` spoofing, adaptive concurrency) means CVE probes fired through it are invisible to WAFs that catch Nuclei instantly. This is a genuine differentiator — **stealth-aware CVE scanning does not exist anywhere else**.

### Architecture

```
assets/
└── cve_templates/
    ├── spring/
    │   ├── CVE-2022-22965.toml   # Spring4Shell RCE
    │   └── CVE-2021-44228.toml   # Log4Shell via headers
    ├── apache/
    │   └── CVE-2021-41773.toml   # Path traversal
    ├── jwt/
    │   └── CVE-2022-21449.toml   # ECDSA null sig bypass
    └── graphql/
        └── CVE-2023-28867.toml   # GraphQL DoS
```

**TOML format** fits the Rust ecosystem naturally over YAML:

```toml
[cve]
id         = "CVE-2022-22965"
severity   = "critical"
tags       = ["spring", "rce", "api"]
references = ["https://spring.io/security/cve-2022-22965"]

[detect]
method       = "POST"
path         = "/?"
headers      = { "Content-Type" = "application/x-www-form-urlencoded" }
body         = "class.module.classLoader.resources.context..."
match_status = [200]
match_body   = "root:"
```

### API-Contextual Intelligence
The real innovation: cross-reference CVE templates against the OpenAPI spec already parsed by `openapi.rs`. Example logic:

- Target exposes `/actuator/*` → probe Spring Boot CVEs specifically
- Target accepts file uploads → probe Spring4Shell, Log4Shell via upload path
- Target exposes `/graphql` → probe GraphQL-specific CVEs first

This turns dumb pattern matching into **context-aware CVE detection** — something Nuclei's template system cannot do without manual configuration.

### Priority CVE Targets for API Contexts

| CVE | Relevance |
|---|---|
| CVE-2023-28867 | GraphQL DoS — already in ApiHunter's wheelhouse |
| CVE-2022-22965 | Spring4Shell — most Java APIs run Spring |
| CVE-2021-44228 | Log4Shell — injectable via API headers/params |
| CVE-2022-21449 | ECDSA null sig — JWT bypass, perfect fit |
| CVE-2023-46604 | Apache ActiveMQ — common API backend |
| CVE-2024-27198 | JetBrains TeamCity API auth bypass |
| CVE-2023-34362 | MOVEit SQL injection via API |

---

## 2. Dynamic User-Agent Pool 🕵️

### Current State (`waf.rs`)
```rust
static USER_AGENTS: &[&str] = &[
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ... Chrome/122.0.0.0",
    // 6 more hardcoded strings
];
```

### Problem
Static pool means repeated scans against the same target present a finite, detectable UA fingerprint set. Any WAF logging UA patterns over time will correlate requests.

### Recommendation
Replace static array with a runtime-fetched pool from a maintained source:

```rust
// On startup, fetch current top browser UAs
async fn fetch_ua_pool() -> Vec<String> {
    // Fetch from https://www.useragents.me/api or similar
    // Fall back to embedded static pool if fetch fails
}
```

Alternatively, ship a `assets/user_agents.txt` updated with each release — same result without runtime network dependency. Also expand beyond Chrome/Firefox/Safari to include:
- Mobile UAs (iOS Safari, Android Chrome) — APIs are increasingly mobile-first
- Headless Chrome with realistic version strings that match current releases

---

## 3. Docker Image 🐳

### Current State
Requires Rust toolchain to build — significant friction for teams without Rust installed.

### Impact
This is the single highest-leverage community growth action. Every CI/CD integration guide starts with `docker pull`. Without a Docker image, ApiHunter is invisible to the DevSecOps audience that would use it most.

### Recommended `Dockerfile`

```dockerfile
# Build stage
FROM rust:1.77-slim AS builder
WORKDIR /app
COPY . .
RUN cargo build --release

# Runtime stage — minimal attack surface
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/api-scanner /usr/local/bin/
COPY --from=builder /app/assets /assets
ENTRYPOINT ["api-scanner"]
```

Single-binary Rust + `debian:bookworm-slim` = ~25MB final image. Publish to:
- `ghcr.io/teycir/apihunter:latest` (GitHub Container Registry, free)
- Optionally `docker.io/teycir/apihunter`

---

## 4. WebSocket Scanner Module 🔌

### Why Now
Modern APIs are not REST-only. GraphQL subscriptions, real-time dashboards, financial trading APIs, and healthcare monitoring systems all use WebSocket. The current scanner is blind to this surface.

### Checks to Implement

```rust
pub struct WebSocketScanner;
// impl Scanner for WebSocketScanner
```

- **Authentication bypass** — connect without `Authorization` header, verify server rejects
- **Origin validation** — connect with arbitrary `Origin:` header, detect if server accepts
- **Message injection** — send malformed JSON frames, detect error disclosure in responses  
- **Subscription abuse** — GraphQL WS subscriptions without auth (common misconfiguration)
- **DoS via frame flooding** — large payload frames, rapid reconnections

### gRPC (Stretch Goal)
gRPC is increasingly common in microservices. The initial implementation could focus on:
- gRPC reflection endpoint exposure (equivalent to GraphQL introspection)
- Unauthenticated service enumeration via reflection
- Missing TLS enforcement detection

---

## 5. Mass Assignment Scanner 🔓

### Why
Mass assignment is the most underdetected API vulnerability class — absent from almost every automated scanner. The `api_security.rs` module does not cover it.

### How It Works
Send extra, unexpected fields in POST/PUT/PATCH request bodies and observe whether the server processes them:

```rust
pub struct MassAssignmentScanner;
```

**Probe strategy:**
1. Parse OpenAPI spec for object schemas (already done in `openapi.rs`)
2. For each schema, identify fields marked `readOnly` or absent from the spec
3. Send those fields in mutation requests
4. Compare response — if the field appears in the response or causes behaviour change, flag it

**Target fields to probe by default:**
```
is_admin, role, roles, admin, verified, email_verified,
account_type, subscription_tier, credit_balance, permissions,
internal_id, created_by, approved
```

This is the automated version of what pentesters do manually in Burp Repeater — and it directly maps to OWASP API6:2023 (Unrestricted Access to Sensitive Business Flows).

---

## 6. OAuth2 / OIDC Scanner Module 🔑

### Why
The existing `jwt.rs` catches JWT implementation flaws but does not test the OAuth2 flow itself. OAuth2 misconfigurations are the root cause of most auth bypass findings in real-world API pentests.

### Checks

```rust
pub struct OAuthScanner;
```

- **`redirect_uri` validation bypass** — append suffixes (`/callback.evil.com`), use open redirectors
- **PKCE downgrade** — attempt auth code flow without PKCE where PKCE should be enforced
- **State parameter CSRF** — omit or replay `state` parameter, verify server rejects
- **Token leakage in referrer** — detect `access_token` in fragment URLs that get logged
- **Client credential exposure** — probe `/.well-known/oauth-authorization-server` for leaked client IDs
- **Implicit flow still enabled** — flag if server still supports deprecated implicit grant
- **Token endpoint brute-force** — verify rate limiting exists on `/oauth/token`

Integration point: feed results from existing `auth.rs` flow into this scanner for context.

---

## 7. Rate Limit Scanner Module 🚦

### Why
OWASP API4:2023 (Unrestricted Resource Consumption) is one of the most common findings but is currently untested by any ApiHunter module.

### Checks

```rust
pub struct RateLimitScanner;
```

- **Absence of rate limiting** — send N rapid requests, detect if server ever returns 429
- **Rate limit bypass via headers** — test `X-Forwarded-For`, `X-Real-IP` rotation to bypass IP-based limits
- **Rate limit bypass via path variation** — `/api/v1/login` vs `/api/v1/login/` vs `/API/V1/LOGIN`
- **Credential stuffing exposure** — detect if auth endpoint rate limits per-account vs per-IP
- **Algorithmic complexity DoS** — send deeply nested GraphQL queries, large sort/filter params

The `waf.rs` adaptive concurrency already models rate limit detection internally — this scanner would expose it as a finding rather than just using it operationally.

---

## 8. Burp Suite Integration 🔗

### Why
The primary red team workflow is Burp → ApiHunter → Nuclei. Making that chain native eliminates manual export/import friction.

### HAR / Burp XML Import

```bash
# Import from Burp XML export
api-scanner --burp-xml burp_export.xml --format sarif

# Import from browser HAR
api-scanner --har session.har --min-severity medium
```

**Implementation:**
- Parse Burp XML (`issues.xml` format) to extract target URLs and already-found issues
- Parse HAR files (JSON, already has `serde_json`) to extract endpoint list
- Feed extracted URLs directly into the runner — reuses all existing scanner modules with zero changes

This makes ApiHunter the natural "second pass" after Burp intercept — take what Burp caught manually, run ApiHunter against that same surface automatically.

### Burp Output Format
Add a `--format burp` output mode that generates an XML file importable as Burp issues — closes the loop so findings appear in Burp's Issues panel alongside manual findings.

---

## 9. AI-Native Output Enhancements 🤖

### Current State
NDJSON and SARIF outputs exist. Both are good for pipelines but not optimised for AI consumption.

### Recommended: `--format ai-context` Mode

Structured JSON output specifically designed to be pasted into Claude/ChatGPT for next-step attack planning:

```json
{
  "scan_summary": {
    "target": "https://api.example.com",
    "endpoints_scanned": 47,
    "auth_method": "Bearer JWT",
    "api_type": "REST + GraphQL"
  },
  "findings": [...],
  "attack_surface": {
    "unauthenticated_endpoints": ["/api/v1/health", "/api/v1/docs"],
    "potential_idor_params": ["user_id", "account_id", "order_id"],
    "sensitive_operations": ["DELETE /api/v1/users/{id}", "POST /api/v1/admin/reset"],
    "exposed_schemas": ["User", "Payment", "AdminConfig"]
  },
  "recommended_next_steps": [
    "Test BOLA on /api/v1/orders/{id} with cross-user credentials",
    "Probe mass assignment on POST /api/v1/users with is_admin field",
    "Test JWT alg=none bypass on authenticated endpoints"
  ]
}
```

The `recommended_next_steps` field is generated by the scanner based on findings — giving the AI model concrete, context-aware starting points rather than raw data.

---

## 10. Community Template Ecosystem 📦

### The Gap
Nuclei's biggest advantage is 10,000+ community-maintained templates. ApiHunter has none. This gap closes only with deliberate community infrastructure.

### Recommended Actions

**Template repository:** Create `github.com/Teycir/apihunter-templates` — separate from the main repo to allow community PRs without affecting the core tool.

**Contribution tooling:**

```bash
# Scaffold a new check template
api-scanner template new --name "spring-actuator-exposure" --severity medium

# Validate a template locally before PR
api-scanner template validate ./my_template.toml

# Test a template against a target
api-scanner template test ./my_template.toml --url https://staging.example.com
```

**Integration:** `--templates-dir` flag already hinted at in architecture — wire up to fetch from the community repo on first run (opt-in).

**awesome-burp-extensions submission:** Get listed on `snoopysecurity/awesome-burp-extensions` — highest-leverage single action for GitHub star growth. Submit a PR to that list with a one-line description.

---

## 11. Import Cookies from JSON (Excalibur/Burp Adjacent) 🍪

### Why
Session import already exists via `--session-file`, but the current on-disk format is:

```json
{
  "hosts": {
    "example.com": { "session": "abc123" }
  }
}
```

Your exported sample (`excalibur-session-2026-03-18T19-25-59-cookies.json`) uses:

```json
{
  "cookies": {
    ".example.com": { "name": "value" }
  }
}
```

Adding native support for this shape removes conversion friction in real workflows.

### Recommendation
- Add explicit format selector on session import: `--session-file-format excalibur`.
- Keep `--session-file` compatible with both schemas: `hosts` and `cookies` (with `auto` detection).
- Optional ergonomic alias: `--cookies-json <FILE>` as shorthand for `--session-file <FILE> --session-file-format excalibur`.
- Normalize domains (`.example.com` → `example.com`) before storing.
- Merge policy: imported cookies + runtime `Set-Cookie` updates should coexist with deterministic overwrite rules.
- Do not print raw cookie values in logs or findings.

---

## Reality Check (Codebase as of 2026-03-18)

- ✅ `Mass assignment` check already exists in `src/scanner/api_security.rs` (active checks path).
- ✅ `Rate limiting` check already exists in `src/scanner/api_security.rs` (burst/429 heuristic).
- ✅ `Session cookie JSON` support already exists via `--session-file` (current schema: `hosts`).
- ⚠️ The roadmap should treat these as **enhancements/refactors**, not net-new modules.

---

## Implementation Roadmap (Checkboxes)

### Phase 1 — Fast Wins (Week 1)
- [ ] Add Docker image (`Dockerfile` + CI publish to GHCR).
- [ ] Add HAR endpoint import (`--har`) into runner input pipeline.
- [x] Add Excalibur cookie import path (`--session-file-format excalibur`) using `cookies -> domain -> name/value` structure.
- [x] Update docs with both supported cookie/session JSON formats and examples.

### Phase 2 — High-Impact Scanning (Weeks 2-4)
- [ ] Implement CVE template engine (`assets/cve_templates/*.toml`) with parser + matcher.
- [ ] Add OpenAPI-context-aware CVE prioritization (template selection by detected tech/endpoints).
- [ ] Split active checks into dedicated modules: `mass_assignment.rs` and `rate_limit.rs`.
- [ ] Expand mass-assignment logic from keyword-based probing to OpenAPI-schema-driven probing.
- [ ] Expand rate-limit logic with bypass probes (`X-Forwarded-For`, path variants, auth endpoint focus).

### Phase 3 — Auth and Protocol Coverage (Weeks 5-7)
- [ ] Implement OAuth2/OIDC scanner module (redirect URI, PKCE, state, implicit flow checks).
- [ ] Implement WebSocket scanner module (origin/auth/message validation).
- [ ] Add gRPC reflection exposure checks (stretch goal).

### Phase 4 — Workflow and Ecosystem (Weeks 8-10)
- [ ] Add Burp XML import (`--burp-xml`) and Burp-compatible output mode (`--format burp`).
- [ ] Add `--format ai-context` output with machine-actionable next-step suggestions.
- [ ] Add community template tooling (`template new|validate|test` commands).
- [ ] Create and seed `apihunter-templates` repository.

### Quality Gates (Apply to Every Phase)
- [ ] Keep test code in `tests/` only (no inline production-file tests).
- [ ] Add unit + integration tests for each new parser/scanner/output mode.
- [ ] Validate scan behavior against at least one known vulnerable lab target per new module.
- [ ] Update `HOWTO.md` + `docs/configuration.md` for every new flag/format.

---

## Overall Assessment

ApiHunter is already the most technically sophisticated API-specific scanner in the open-source space for stealth and false-positive reduction. The code quality is production-grade — clean trait system, proper async, adaptive concurrency, dual-client auth architecture.

The gap is **coverage breadth and community infrastructure**, not architecture. The architecture is already correct. Every improvement above is additive — nothing requires rethinking the core.

A CVE module + Docker image alone would make this the default recommendation for any API red team engagement over Nuclei for hardened targets with WAF protection. That is a realistic 3-month milestone for a solo maintainer.

---

*Analysis based on direct code review of `src/waf.rs`, `src/http_client.rs`, `src/auth.rs`, `src/scanner/mod.rs`, `src/scanner/api_security.rs`, `src/scanner/jwt.rs`, `src/scanner/graphql.rs`, `src/scanner/openapi.rs`, `src/scanner/cors.rs`, `src/discovery/*`, and `HOWTO.md`.*
