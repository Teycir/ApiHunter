---
author: teycir ben soltane
email: teycir@pxdmail.net
website: teycirbensoltane.tn
last_updated: 2026-03-14
tags: [scanners, cors, csp, graphql, api-security, jwt, openapi]
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

**Detects:**
- Missing security schemes in the spec
- Operations without explicit security requirements
- File upload endpoints
- Deprecated operations still present in the spec
