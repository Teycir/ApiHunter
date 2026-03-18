---
author: teycir ben soltane
email: teycir@pxdmail.net
website: teycirbensoltane.tn
last_updated: 2026-03-18
tags: [scanners, cors, csp, graphql, api-security, jwt, openapi, mass-assignment, websocket, active-checks]
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
- **Rate-limit detection** — controlled burst probes to detect 429 (Too Many Requests) thresholds

### JWT Active Checks
- **Algorithm confusion** — attempts RS256 → HS256 substitution attacks
- **Key ID injection** — probes for `kid` header manipulation vulnerabilities

### GraphQL Active Checks
- **Complexity/depth bombs** — sophisticated query structures to test depth limits
- **Query cost analysis** — attempts to measure GraphQL cost limiting

⚠️ **Warning:** Active checks generate significantly higher request volume and may:
- Trigger WAF/IDS alerts and rate limiting
- Disrupt service monitoring or analytics
- Be treated as security attacks depending on your environment

Only enable in controlled environments with proper authorization and testing windows.
