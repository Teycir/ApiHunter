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

**Detects:**
- `mass_assignment/reflected-fields` when crafted sensitive fields (for example `is_admin`, `role`, `permissions`) are reflected
- `mass_assignment/persisted-state-change` when reflected fields also appear newly elevated in a post-injection confirmation read

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
- `assets/cve_templates.toml`

Current translated checks include:
- `cve/cve-2022-22947/spring-cloud-gateway-actuator-exposed`
- `cve/cve-2021-29442/nacos-auth-bypass-signal`
- `cve/cve-2020-13945/apisix-default-admin-key`

**Detects:**
- CVE-specific exposure signals based on:
  - HTTP status constraints
  - response body indicators
  - required request headers (for example known-default API keys)

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
- **Catalog extensibility** — add or tune templates via `assets/cve_templates.toml` without changing scanner code

⚠️ **Warning:** Active checks generate significantly higher request volume and may:
- Trigger WAF/IDS alerts and rate limiting
- Disrupt service monitoring or analytics
- Be treated as security attacks depending on your environment

Only enable in controlled environments with proper authorization and testing windows.
