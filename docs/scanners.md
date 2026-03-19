---
author: teycir ben soltane
email: teycir@pxdmail.net
website: teycirbensoltane.tn
last_updated: 2026-03-19
tags: [scanners, cors, csp, graphql, api-security, jwt, openapi, mass-assignment, oauth, oidc, rate-limit, cve, templates, websocket, active-checks]
category: Scanner Modules
---

# Scanner Modules

This document describes all built-in scanner modules and their detection capabilities.

## Quick Reference

| Scanner | Type | Severity Range | Key Detections |
|---------|------|----------------|----------------|
| [CORS](#cors-scannercors) | Passive | Low-High | Wildcard origins, reflected origins, null origin, regex bypass, missing Vary |
| [CSP](#csp-scannercsp) | Passive | Info-Medium | Missing CSP, unsafe-inline/eval, wildcard sources, bypassable CDNs |
| [GraphQL](#graphql-scannergraphql) | Passive | Info-High | Introspection enabled, sensitive fields, batching, alias DoS, IDE exposure |
| [API Security](#api-security-scannerapi_security) | Passive | Info-Medium | Missing headers, version disclosure, unauth access, debug endpoints |
| [JWT](#jwt-scannerjwt) | Passive | Medium-Critical | alg=none, weak secrets, missing expiry, sensitive claims |
| [OpenAPI](#openapi-scanneropenapi) | Passive | Low-Medium | Missing security schemes, unsecured operations, file uploads |
| [Mass Assignment](#mass-assignment-scannermass_assignment) | Active | High-Critical | Reflected fields, persisted changes, privilege escalation |
| [OAuth/OIDC](#oauth2--oidc-scanneroauth_oidc) | Active | Medium-High | Redirect URI bypass, missing state, PKCE issues, unsafe flows |
| [Rate Limit](#rate-limit-scannerrate_limit) | Active | Medium | Missing throttling, bypass via IP headers |
| [CVE Templates](#cve-templates-scannercve_templates) | Active | Varies | Template-driven CVE detection (168 templates currently) |
| [WebSocket](#websocket-scannerwebsocket) | Active | Low-Medium | Upgrade acceptance, missing origin validation |

---

## CORS (`scanner::cors`)

Checks for overly permissive `Access-Control-Allow-Origin` responses.

**Detects:**
- Wildcard origin (`*`) on credentialed responses
- Reflected `Origin` header without allowlist validation
- `null` origin acceptance

---

## CSP (`scanner::csp`)

Analyses `Content-Security-Policy` headers.

**Detects:**
- Missing CSP header
- `unsafe-inline` / `unsafe-eval` in script-src
- Wildcard (`*`) source directives
- Missing `default-src` fallback

---

## GraphQL (`scanner::graphql`)

Probes common GraphQL endpoints for misconfigurations.

**Detects:**
- Introspection enabled in production
- Batch query support (DoS amplification risk)
- Missing depth/complexity limits (heuristic)

---

## API Security (`scanner::api_security`)

General API hardening checks.

**Detects:**
- Missing `X-Content-Type-Options`
- Missing `X-Frame-Options` / `frame-ancestors`
- Server version disclosure via `Server` header
- Unauthenticated access to common sensitive paths

---

## JWT (`scanner::jwt`)

Deep inspection of JWTs found in responses.

**Detects:**
- `alg=none` tokens
- Weak HS256 secrets (curated candidate list)
- Long-lived or missing `exp` claim
- Sensitive claims in payload

---

## OpenAPI (`scanner::openapi`)

Analyses OpenAPI / Swagger specs discovered at common paths.

The OpenAPI scanner discovers JSON/YAML spec files at common endpoints:
- `/swagger.json`, `/api/swagger.json`
- `/openapi.json`, `/api/openapi.json`
- `/v1/openapi.json`, `/v2/openapi.json`
- `/openapi.yaml`, `/swagger.yaml`

**Detects:**
- Missing security schemes in the spec
- Operations without explicit security requirements
- File upload endpoints (e.g., `multipart/form-data`)
- Deprecated operations still present in the spec
- Unsecured endpoints that should require authentication

---

## Mass Assignment (`scanner::mass_assignment`)

Dedicated active-checks scanner for mass-assignment style field injection probes.

This scanner currently runs only when `--active-checks` is enabled.
With `--dry-run`, it emits informational findings about intended probes and does not send mutation requests.

**Detects:**
- `mass_assignment/reflected-fields` when crafted sensitive fields (for example `is_admin`, `role`, `permissions`) are reflected
- `mass_assignment/persisted-state-change` when reflected fields also appear newly elevated in a post-injection confirmation read
- `mass_assignment/dry-run` when dry-run mode is enabled for active checks

---

## OAuth2 / OIDC (`scanner::oauth_oidc`)

Active-checks scanner for OAuth authorization endpoint and OIDC metadata hardening signals.

This scanner currently runs only when `--active-checks` is enabled.

**Detects:**
- `oauth/redirect-uri-not-validated` when authorize endpoints redirect to attacker-controlled callbacks
- `oauth/state-not-returned` when supplied `state` is not round-tripped in authorization redirects
- `oauth/pkce-metadata-missing` when OIDC metadata omits PKCE method declarations
- `oauth/pkce-s256-not-supported` when metadata does not advertise `S256`
- `oauth/pkce-plain-supported` when weak PKCE `plain` is enabled
- `oauth/implicit-flow-enabled` when `response_types_supported` includes token-bearing implicit/hybrid flows
- `oauth/ropc-grant-enabled` when password grant is advertised

---

## Rate Limit (`scanner::rate_limit`)

Active-checks scanner for API4-style throttling and basic bypass signals.

This scanner currently runs only when `--active-checks` is enabled.

**Detects:**
- `rate_limit/not-detected` when burst probes do not trigger 429 and rate-limit headers are absent
- `rate_limit/missing-retry-after` when 429 responses omit Retry-After guidance
- `rate_limit/ip-header-bypass` when spoofed client IP headers appear to bypass active throttling

---

## CVE Templates (`scanner::cve_templates`)

Active-checks scanner powered by a TOML template catalog translated from Nuclei-style API CVE checks.

This scanner currently runs only when `--active-checks` is enabled.

Template catalog location:
- `assets/cve_templates/*.toml`

Current local catalog size: `168` templates.

Curated hardened examples include:
- `cve/cve-2022-22947/spring-cloud-gateway-actuator-exposed`
- `cve/cve-2022-24288/airflow-example-dag-params-rce-signal`
- `cve/cve-2020-3452/cisco-asa-ftd-path-traversal-signal`
- `cve/cve-2021-29442/nacos-auth-bypass-signal`
- `cve/cve-2021-29441/nacos-user-agent-auth-bypass-signal`
- `cve/cve-2020-13945/apisix-default-admin-key`
- `cve/cve-2021-45232/apisix-dashboard-unauthorized-export`

**Detects:**
- CVE-specific exposure signals based on:
  - HTTP status constraints
  - response body indicators
  - response body/header regex constraints
  - required request headers (for example known-default API keys)
  - optional safe preflight request chains (`GET`/`HEAD`/`OPTIONS`) before the main probe
  - optional baseline-vs-confirm differentials for bypass-style checks

Regression target lists kept in-repo:
- `targets/cve-regression-vulhub-local.txt` (local true-positive CVE validation set)
- `targets/cve-regression-real-public.txt` (real internet negative-regression set)
- `docs/lab-setup.md` (reproducible Vulhub compose scenarios and fixture workflow)

Local true-positive mapping:
- `http://127.0.0.1:18080/actuator` -> `CVE-2022-22947`
- `http://127.0.0.1:18848/nacos` -> `CVE-2021-29442`
- `http://127.0.0.1:18851/nacos` -> `CVE-2021-29441` (requires auth-enabled Nacos baseline)
- `http://127.0.0.1:19080/apisix/admin` -> `CVE-2020-13945`
- `http://127.0.0.1:19000/apisix/admin` -> `CVE-2021-45232`

Vulhub-native Nacos mapping (preferred for reproducibility):
- `vulhub/nacos/CVE-2021-29441/docker-compose.yml` -> `http://127.0.0.1:8848/nacos`
- `vulhub/nacos/CVE-2021-29442/docker-compose.yml` -> `http://127.0.0.1:8848/nacos`
- run one scenario at a time (both bind `8848`)

Example true-positive regression run:
```bash
./target/debug/apihunter \
  --urls targets/cve-regression-vulhub-local.txt \
  --no-filter --no-discovery --active-checks \
  --no-cors --no-csp --no-graphql --no-jwt --no-openapi \
  --format ndjson --output /tmp/cve_tp.ndjson \
  --quiet --delay-ms 0 --fail-on critical

rg '"check":"cve/' /tmp/cve_tp.ndjson
```

Real-data hardening tests:
- `tests/cve_templates_real_data.rs` replays captured live payloads from `tests/fixtures/real_cve_payloads/`
- `tests/cve_templates_upstream_parity.rs` validates CVE/source linkage against pinned upstream Nuclei snapshots in `tests/fixtures/upstream_nuclei/`

---

## WebSocket (`scanner::websocket`)

Initial active-checks scaffold for WebSocket surface discovery.

This scanner currently runs only when `--active-checks` is enabled.

**Detects:**
- WebSocket upgrade acceptance on common WS paths (informational exposure signal)
- Possible missing origin validation when an attacker origin is also accepted

---

## Active Checks (Opt-In)

When `--active-checks` is enabled, additional potentially invasive probes are performed.
These should only be used in controlled environments or with explicit permission.

### CORS Active Checks
- **OPTIONS request analysis** — probes HTTP method exposure via `OPTIONS` verb
- **Method tampering** — tests response to uncommon HTTP methods

### API Security Active Checks
- **Verb tampering** — attempts `TRACE`, `PATCH`, `HEAD` (if not already detected passively)
- **BOLA/IDOR probing** — numeric ID swap tests on detected endpoints

### JWT Active Checks
- **Algorithm confusion** — attempts RS256 → HS256 substitution attacks
- **Key ID injection** — probes for `kid` header manipulation vulnerabilities

### GraphQL Active Checks
- **Complexity/depth bombs** — sophisticated query structures to test depth limits
- **Query cost analysis** — attempts to measure GraphQL cost limiting

### OAuth/OIDC Active Checks
- **Authorization redirect probing** — tests redirect URI handling and state round-trip behavior
- **OIDC discovery analysis** — evaluates metadata for PKCE and legacy/unsafe flow exposure

### Rate-Limit Active Checks
- **Burst throttling probe** — controlled bursts to test 429 enforcement and rate-limit signaling
- **Header-based bypass probe** — tests whether client IP headers can evade throttling decisions

### CVE Template Active Checks
- **Template-driven CVE probes** — translated low-impact API CVE checks executed against host-contextual paths
- **Regex + DSL translation support** — template constraints can include translated regex and supported DSL operators
- **Safe preflight chains** — optional non-mutating setup requests run before the primary probe
- **Catalog extensibility** — add or tune templates via `assets/cve_templates/*.toml` without changing scanner code

⚠️ **Warning:** Active checks generate significantly higher request volume and may:
- Trigger WAF/IDS alerts and rate limiting
- Disrupt service monitoring or analytics
- Be treated as security attacks depending on your environment

Only enable in controlled environments with proper authorization and testing windows.
