---
author: teycir ben soltane
email: teycir@pxdmail.net
website: teycirbensoltane.tn
last_updated: 2026-04-03
tags: [scanners, cors, csp, graphql, api-security, api-versioning, response-diff, grpc, protobuf, jwt, openapi, mass-assignment, oauth, oidc, rate-limit, cve, templates, websocket, active-checks]
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
| [API Security](#api-security-scannerapi_security) | Passive + Active | Info-Critical | Header hardening gaps, debug exposure, IDOR/BOLA, blind SSRF callback probe signals |
| [JWT](#jwt-scannerjwt) | Passive | Medium-Critical | alg=none, weak secrets, missing expiry, sensitive claims |
| [OpenAPI](#openapi-scanneropenapi) | Passive | Low-Medium | Missing security schemes, unsecured operations, file uploads |
| [API Versioning](#api-versioning-scannerapi_versioning) | Passive | Info-Medium | Version headers, legacy version exposure, response diff drift |
| [gRPC/Protobuf](#grpcprotobuf-scannergrpc_protobuf) | Passive + Active | Info-Medium | gRPC transport hints, protobuf signals, reflection/health probe surface |
| [Mass Assignment](#mass-assignment-scannermass_assignment) | Active | High-Critical | Reflected fields, persisted changes, privilege escalation |
| [OAuth/OIDC](#oauth2--oidc-scanneroauth_oidc) | Active | Medium-High | Redirect URI bypass, missing state, PKCE issues, unsafe flows |
| [Rate Limit](#rate-limit-scannerrate_limit) | Active | Medium | Missing throttling, bypass via IP headers |
| [CVE Templates](#cve-templates-scannercve_templates) | Active | Varies | Template-driven CVE detection (168 templates currently) |
| [WebSocket](#websocket-scannerwebsocket) | Active | Low-Medium | Upgrade acceptance, missing origin validation |

---

## Finding Structure

Each scanner emits standardized findings with fields such as:
- `check` (stable check ID, for example `cors/wildcard-origin`)
- `scanner` (module name, for example `cors`)
- `severity`, `detail`, and `evidence`
- `url` and `timestamp`

This keeps scanner output machine-consumable for NDJSON/SARIF pipelines while preserving analyst-readable context.

---

## Signal Quality Guidance

| Scanner | High-confidence signals | Typical false-positive sources | Typical false-negative sources |
|---------|--------------------------|--------------------------------|--------------------------------|
| CORS | Wildcard/reflected origins on credentialed responses | Reflection on endpoints that never handle sensitive data | CORS checks enforced only after auth/session |
| CSP | Missing CSP and unsafe directives (`unsafe-inline`, `unsafe-eval`) | Transitional CSP policies in staged rollouts | CSP applied only on edge/CDN path not reached by probe |
| GraphQL | Introspection and IDE exposure on public endpoints | Public demo schemas intentionally exposed | GraphQL endpoint hidden behind auth gateway |
| API Security | Missing hardening headers, debug route exposure | Non-prod endpoints exposed in shared environments | Sensitive routes only visible after authenticated crawl |
| JWT | `alg=none`, weak secret, sensitive claim leakage | Synthetic/non-production tokens in test fixtures | JWT never appears in sampled traffic |
| OpenAPI | Missing security requirements and exposed upload routes | Internal specs intentionally broad while backend enforces auth | Spec unavailable or split into private fragments |
| API Versioning | Version disclosure, legacy version reachability, response drift across benign variants | Planned transition windows with intentionally parallel versions | Versioned routes outside discovered path corpus |
| gRPC/Protobuf | gRPC transport/reflection hints with metadata confirmation | Edge proxies may emit gRPC-like headers without externally reachable RPC methods | gRPC surface hosted on separate ports/hosts not included in seed/discovery scope |
| Mass Assignment | Persisted sensitive-field elevation after mutation | Echoed request fields not actually persisted | Server-side validators block mutation path silently |
| OAuth/OIDC | Redirect validation bypass and weak PKCE metadata | Lab IdP environments with intentionally relaxed defaults | Runtime auth policy differs from published metadata |
| Rate Limit | Missing throttling signal under burst + bypass attempts | Upstream CDN/rate controls mask application behavior | Long windows not triggered by short probe windows |
| CVE Templates | Multi-condition template hits with status/body/header evidence | Generic fingerprint overlap on shared middleware pages | Vulnerable path/context never discovered from seed URLs |
| WebSocket | Upgrade acceptance + attacker-origin acceptance | Public anonymous WS intentionally exposed | Required handshake auth headers not provided in probe |

---

## False-Positive Expectation Model

ApiHunter does not claim one universal FP percentage across all environments.
Different target architectures, auth boundaries, and WAF behavior can change outcomes substantially.

Use these tendency bands for planning:

- **Low**: scanner includes multiple validation guards; findings are usually actionable with manual confirmation.
- **Medium**: findings are often useful, but environment context regularly changes exploitability.
- **High**: scanner is intentionally sensitive and can produce operational noise without environment scoping.

The table below combines what each module checks, what finding IDs look like, and the expected FP tendency.

---

## Module Check Catalog

| Module | What is checked | Finding IDs (examples/patterns) | FP tendency | Main FP drivers |
|--------|------------------|----------------------------------|-------------|-----------------|
| CORS | ACAO wildcard/reflection/null, regex bypass probes, preflight method exposure, missing `Vary: Origin` | `cors/wildcard-no-credentials`, `cors/reflected-origin`, `cors/null-origin`, `cors/regex-bypass-suffix`, `cors/regex-bypass-prefix`, `cors/preflight-unsafe-methods`, `cors/missing-vary-origin` | Medium | Reflection on non-sensitive/public endpoints; permissive CORS intended for public APIs |
| CSP | Missing CSP, missing required directives, unsafe source directives, bypassable script CDNs, missing frame-ancestors | `csp/missing`, `csp/missing-directive/<directive>`, `csp/unsafe-source/<token>`, `csp/bypassable-cdn`, `csp/missing-frame-ancestors`, `csp/report-only` | Low-Medium | Transitional CSP rollout, report-only deployments, contexts that require script flexibility |
| GraphQL | Introspection, sensitive schema names, field suggestions, batching support, alias amplification, IDE exposure | `graphql/introspection-enabled`, `graphql/sensitive-schema-fields`, `graphql/field-suggestions`, `graphql/batching-enabled`, `graphql/alias-amplification`, `graphql/playground-exposed`, `graphql/endpoint-detected` | Medium | Public/demo schemas, intentionally enabled playground in lower environments |
| API Security | Secret patterns in body, stack/error disclosure, TRACE/write methods, debug/admin endpoint exposure, directory listing, missing `security.txt`, hardening header checks, active IDOR/BOLA, active blind SSRF callback probes, gateway fingerprint/bypass checks | `api_security/secret-in-response/<slug>`, `api_security/error-disclosure/<slug>`, `api_security/http-method/trace-enabled`, `api_security/http-method/write-methods-enabled`, `api_security/debug-endpoint<path>`, `api_security/directory-listing<path>`, `api_security/security-txt/missing`, `api_security/headers/<slug>`, `api_security/headers/<slug>-weak`, `api_security/unauthenticated-access`, `api_security/partial-unauth-access`, `api_security/idor-id-enumerable`, `api_security/idor-cross-user`, `api_security/blind-ssrf-probe-dispatched`, `api_security/blind-ssrf-token-reflected`, `api_security/blind-ssrf-probe-dry-run`, `api_security/gateway-detected`, `api_security/gateway-bypass-suspected`, `api_security/gateway-bypass-dry-run` | Medium | Public status/debug routes in non-prod; frontend keys flagged as potential secrets; expected unauth behavior for public resources |
| JWT | `alg=none`, suspicious `kid`, sensitive claims, missing/long expiry, weak HS256 secret checks, RS256/HS256 confusion probe (active) | `jwt/alg-none`, `jwt/suspicious-kid`, `jwt/sensitive-claims`, `jwt/no-exp`, `jwt/long-lived`, `jwt/weak-secret`, `jwt/alg-confusion` | Low-Medium | Test/demo tokens, intentionally long-lived service tokens, non-security JWT usage patterns |
| OpenAPI | Missing security schemes, operations without security requirements, upload surfaces, deprecated operations | `openapi/no-security-schemes`, `openapi/unauthenticated-operations`, `openapi/file-upload`, `openapi/deprecated-operations` | Medium | Specs lagging behind backend auth enforcement; mixed public/private operations in shared specs |
| API Versioning | Version headers, deprecation/sunset hints, adjacent version probes, benign query/version response diff analysis (plus optional deep variants) | `api_versioning/version-header-disclosed`, `api_versioning/deprecation-signaled`, `api_versioning/multiple-active-versions`, `api_versioning/legacy-version-still-accessible`, `response_diff/query-variant-server-error`, `response_diff/query-variant-drift`, `response_diff/version-variant-server-error`, `response_diff/version-variant-drift`, `response_diff/deep-variant-server-error`, `response_diff/deep-variant-drift` | Medium | Multiple supported versions during planned migration can look risky without environment context |
| gRPC/Protobuf | gRPC content-type/header signals and active reflection/health path probes | `grpc_protobuf/grpc-transport-detected`, `grpc_protobuf/protobuf-signal-detected`, `grpc_protobuf/grpc-reflection-or-health-surface` | Medium | gRPC metadata can appear at proxies even when backend RPC methods remain unavailable |
| Mass Assignment (active) | Sensitive field injection reflection and persistence confirmation, dry-run signal | `mass_assignment/reflected-fields`, `mass_assignment/persisted-state-change`, `mass_assignment/dry-run` | Low-Medium | Echoed request bodies mistaken for persistence if follow-up state context is weak |
| OAuth/OIDC (active) | Redirect URI validation, `state` round-trip, PKCE metadata presence/strength, implicit and password grant exposure | `oauth/redirect-uri-not-validated`, `oauth/state-not-returned`, `oauth/pkce-metadata-missing`, `oauth/pkce-s256-not-supported`, `oauth/pkce-plain-supported`, `oauth/implicit-flow-enabled`, `oauth/ropc-grant-enabled` | Medium | Lab IdP configs intentionally permissive; metadata not matching runtime policy |
| Rate Limit (active) | Burst throttling response, missing `Retry-After`, spoofed IP header bypass attempts | `rate_limit/not-detected`, `rate_limit/missing-retry-after`, `rate_limit/ip-header-bypass`, `rate_limit/check-failed` | Medium-High | Long-window throttles not triggered by short bursts; CDN/gateway shielding app-level controls |
| CVE Templates (active) | Template-driven CVE probes with status/body/header matchers, optional preflight, optional baseline-vs-confirm differential | `cve/<cve-id>/<template-slug>` (from template catalog) | Medium | Generic fingerprint overlap, broad context hints, target path mismatch to actual vulnerable surface |
| WebSocket (active) | Upgrade acceptance and attacker-origin acceptance on common WS paths | `websocket/upgrade-endpoint`, `websocket/origin-not-validated` | Medium | Public anonymous sockets intentionally allowed; origin checks delegated upstream |

---

## Measuring False-Positive Rate In Your Environment

Use your own staging/production-like target set to get actionable FP rates:

1. Run a baseline scan and keep raw NDJSON.
2. Triage findings into `confirmed` vs `false_positive`.
3. Compute per-module FP rate from the triage labels.

Example workflow:

```bash
./target/release/apihunter \
  --urls targets/cve-regression-real-public.txt \
  --format ndjson \
  --output /tmp/apihunter_findings.ndjson

# Example triage file schema:
# {"check":"cors/reflected-origin","scanner":"cors","triage":"false_positive"}
# {"check":"jwt/alg-none","scanner":"jwt","triage":"confirmed"}

jq -r 'select(.triage=="false_positive") | .scanner' /tmp/triage.ndjson \
  | sort | uniq -c

jq -r '.scanner' /tmp/triage.ndjson | sort | uniq -c
```

Recommended reporting metric:
- `fp_rate(scanner) = false_positives(scanner) / total_triaged_findings(scanner)`

Track this over time after gateway/WAF/auth changes to catch scanner noise drift early.

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
- Active mutation fuzzing signals (`graphql/mutation-fuzzing-*`) when `--active-checks` is enabled

---

## API Security (`scanner::api_security`)

General API hardening checks.

**Detects:**
- Missing `X-Content-Type-Options`
- Missing `X-Frame-Options` / `frame-ancestors`
- Server version disclosure via `Server` header
- Unauthenticated access to common sensitive paths
- Active blind SSRF callback probe signals (`api_security/blind-ssrf-*`) when `--active-checks` is enabled and `APIHUNTER_OAST_BASE` is set
- API gateway fingerprint signals (`api_security/gateway-detected`)
- Gateway bypass probe status flips on trusted edge headers (`api_security/gateway-bypass-*`)

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

## API Versioning (`scanner::api_versioning`)

Passive scanner focused on API lifecycle drift and version-transition risk.

**Detects:**
- Version metadata disclosure in response headers (`api-version`, `x-api-version`, etc.)
- Deprecation/sunset header signals
- Concurrent active sibling versions (for example `v1` + `v2` both reachable)
- Legacy version exposure for current versioned endpoints
- Response drift checks under benign query/version variants (`response_diff/*`)
- Optional deep response-diff variants (query/header permutations) when `--response-diff-deep` is enabled

---

## gRPC/Protobuf (`scanner::grpc_protobuf`)

Passive-plus-active scanner for detecting gRPC/protobuf API surface signals.

**Detects:**
- gRPC transport metadata from response headers/content-type
- Protobuf-oriented surface hints from metadata/path shape
- Reflection/health probe surface on known gRPC paths when active checks are enabled

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
  - runtime template quality gates (invalid/unsafe request templates are skipped at load)
  - segment-aware context matching (reduces broad substring-triggered probes)

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
- **Blind SSRF callback probing** — injects callback-style query parameters with OAST correlation tokens (`APIHUNTER_OAST_BASE`)
- **Gateway bypass probing** — tests trusted edge routing headers (`X-Original-URL`, `X-Rewrite-URL`, `X-Forwarded-*`) against blocked baseline paths

### API Versioning Active-Diff Checks
- **Deep response-diff mode** — optional query/header permutation probes for edge-case parser/cache/gateway drift (`--response-diff-deep`)

### gRPC/Protobuf Active Checks
- **Reflection/health surface probe** — POST probes to common reflection/health RPC paths and confirms gRPC-like metadata signals

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
