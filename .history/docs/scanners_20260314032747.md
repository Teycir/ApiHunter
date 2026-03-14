# Scanner modules

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
