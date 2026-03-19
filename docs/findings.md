---
author: teycir ben soltane
email: teycir@pxdmail.net
website: teycirbensoltane.tn
last_updated: 2026-03-14
tags: [findings, severity, interpretation, remediation, results]
category: Results & Remediation
---

# Understanding ApiHunter Findings

This document explains how to interpret findings, understand severity levels, and prioritize remediation.

---

## Severity Levels

Findings are classified into five severity categories (from lowest to highest risk):

### 🟢 Info
Non-blocking observations or configuration notes.
- **Example:** Server header version disclosure
- **Action:** Track but deprioritize unless combined with other findings

### 🟡 Low
Minor security issues that typically require additional context to exploit.
- **Example:** Weak CSP with only minor bypasses
- **Action:** Plan remediation in next maintenance window

### 🟠 Medium  
Notable misconfigurations that could enable attacks under reasonable circumstances.
- **Example:** Missing `HSTS` header, write methods enabled without auth verification
- **Action:** Schedule remediation within weeks

### 🔴 High
Significant security flaws enabling direct attacks or credential exposure.
- **Example:** CORS wildcard origin, unsafe CSP directives (`unsafe-eval`, `unsafe-inline`)
- **Action:** Prioritize for rapid remediation (within days)

### 🟣 Critical
Immediate threats to confidentiality, integrity, or availability.
- **Example:** Exposed API keys or secrets in responses, authentication bypass signals
- **Action:** Immediate investigation and remediation (within hours/minutes)

---

## Common Finding Categories

### CORS Findings

**Wildcard CORS** (Medium)
```
Access-Control-Allow-Origin: *
```
- Allows any origin to make credentialed requests
- **Remediation:** Specify allowed origins explicitly and use `Vary: Origin` header

**Reflected CORS** (High/Medium)
```
Access-Control-Allow-Origin: <reflected-origin>
```
- Blindly reflects the requesting origin without validation
- **Remediation:** Validate origins against a whitelist before reflecting

**Null Origin Acceptance** (Medium)
```
Access-Control-Allow-Origin: null
```
- Some browsers send `Origin: null` in certain contexts; accepting it compromises security
- **Remediation:** Remove `null` from the origin allowlist

---

### CSP Findings

**Missing CSP** (Medium)
- **Remediation:** Add a restrictive `default-src` CSP header; prevent inline scripts/styles

**CSP with `unsafe-inline`** (High)
- Defeats XSS protections by allowing inline scripts and styles
- **Remediation:** Move inline code to external files; use nonces or hashes for dynamic scripts

**CSP with `unsafe-eval`** (High)
- Allows `eval()`, `setTimeout()` with strings, `new Function()`, etc.
- **Remediation:** Refactor code to avoid `eval()` patterns; use structured data and APIs

**Wildcard in CSP** (High)
```
script-src *
```
- Allows loading scripts from any host
- **Remediation:** Use specific domains; prefer SRI (Subresource Integrity) for external resources

---

### API Security Findings

**Debug Endpoints Exposed** (High)
- Endpoints like `/_profiler`, `/_debug/` are accessible publicly
- **Remediation:** Restrict to localhost or remove in production builds

**Write Methods Enabled** (Medium)
```
PUT, DELETE, PATCH accepted on unauthenticated endpoints
```
- **Remediation:** Verify these endpoints require authentication; enforce explicitly

**Header Disclosure** (Low/Medium)
- Server version, technology stack revealed in headers
- **Remediation:** Remove or mask `Server`, `X-Powered-By`, `X-AspNet-Version` headers

**Missing Security Headers** (Medium)
- `X-Content-Type-Options: nosniff` prevents MIME sniffing
- `X-Frame-Options: DENY` prevents clickjacking
- `HSTS` enforces HTTPS
- **Remediation:** Add these headers to all HTTP responses

---

### JWT Findings

**`alg=none` Token** (Critical)
- JWT header specifies `"alg":"none"`, bypassing signature verification
- **Remediation:** Reject tokens with `alg=none`; validate algorithm server-side

**Weak HS256 Secret** (Critical)
- HMAC-SHA256 key is guessable (common word, short, predictable)
- **Remediation:** Use strong, random cryptographic keys (≥128 bits entropy)

**Long-Lived Token** (Medium)
- Token has no expiration or very distant `exp` claim
- **Remediation:** Set reasonable token lifetime (e.g., 15 minutes for access tokens)

**Sensitive Data in JWT** (Medium)
- Decoded JWT body contains passwords, secrets, or PII
- **Remediation:** Tokens should contain minimal claims; store sensitive data server-side

---

### GraphQL Findings

**Introspection Enabled** (Medium/High)
- GraphQL schema is publicly queryable via introspection
- **Remediation:** Disable introspection in production; require authentication if needed

**Batch Queries Supported** (Medium)
- Multiple queries in a single request amplify DoS attacks
- **Remediation:** Limit batch size or disable if not needed by clients

**No Depth Limits** (Medium)
- Deeply nested queries can exhaust server resources
- **Remediation:** Implement query depth and complexity limits

---

### OpenAPI/Swagger Findings

**Unsecured Endpoints** (High)
- OpenAPI spec shows endpoints without `security` requirement
- **Remediation:** Add security schemes to the spec and enforce in code

**Deprecated Operations** (Medium)
- Old API versions still served with known issues
- **Remediation:** Sunset deprecated operations; force clients to upgrade versions

**File Upload Endpoints** (Medium)
- Endpoints accepting file uploads may be vulnerable to arbitrary file upload
- **Remediation:** Validate file extensions, MIME types, size; scan uploads for malware

---

## Interpreting the Output

### NDJSON Format

Each line is a valid JSON object representing one finding:

```json
{
  "url": "https://api.example.com/",
  "check": "csrf/missing",
  "title": "Missing CSRF Protection",
  "severity": "MEDIUM",
  "detail": "No CSRF token detected on form endpoints.",
  "evidence": "Endpoint: /api/create-user\nMethod: POST\nNo _csrf or token field",
  "scanner": "api_security",
  "timestamp": "2026-03-14T05:40:30.123456Z"
}
```

Parse these with standard JSON tools:
```bash
jq '.severity' results.ndjson | sort | uniq -c
jq 'select(.severity == "CRITICAL")' results.ndjson
```

### SARIF Format

SARIF output is suitable for GitHub Code Scanning and other enterprise platforms:
```bash
./apihunter --urls ./targets.txt --format sarif --output results.sarif
```

Upload to GitHub:
```bash
github-cli security code-scanning upload-sarif results.sarif
```

### Exit Codes

- `0` — No findings, no errors (clean)
- `1` — Findings detected
- `2` — Errors during scanning
- `3` — Both findings and errors

Use in CI/CD:
```bash
./apihunter --urls ./targets.txt --fail-on critical
EXIT=$?
if (( EXIT )); then
  echo "Critical findings detected!"
  exit 1
fi
```

---

## Remediation Priority Matrix

| Severity | Risk | Timeline | Action |
|----------|------|----------|--------|
| Critical | Immediate exploitation likely | Hours | Emergency hotfix or disable service |
| High | Exploitation under normal usage | Days | Schedule urgent patch |
| Medium | Exploitation requires effort/context | Weeks | Include in regular sprints |
| Low | Theoretical or requires chain | Next release | Document and track |
| Info | Advisory | Optional | Monitor for trends |

---

## False Positives and Limitations

### Known Limitations

- **WAF/Middleware:** Some checks may be filtered by WAF, giving false negatives
- **Client-side validation:** Apparent lack of server checks might be intentional (client-only API)
- **Cached responses:** Some headers may be cached and not reflect current config
- **Rate limiting:** May interrupt multi-check probes and yield incomplete results

### Reducing False Positives

1. **Baseline before deployment** — run against staging/dev first
2. **Review evidence** — always check the `evidence` field
3. **Test manually** — confirm suspicious findings with manual requests
4. **Exclude paths** — use discovery filters if needed
5. **Check logs** — correlate with application logs to understand context

### Reporting Issues

If you encounter false positives or inaccurate findings:
1. Note the exact check ID (e.g., `cors/wildcard`)
2. Include the URL and response headers/body
3. Report via the project's GitHub issues with `[false-positive]` prefix

