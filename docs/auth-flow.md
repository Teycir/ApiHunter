---
author: teycir ben soltane
email: teycir@pxdmail.net
website: teycirbensoltane.tn
last_updated: 2026-03-14
tags: [auth, flow, configuration]
category: Authentication Flow
---

# Auth Flow

ApiHunter can execute a JSON-defined authentication flow before a scan starts.
This allows you to log in, extract tokens, and inject credentials into every
subsequent request. You can also define a second flow for cross-user IDOR checks.

## CLI Flags

- `--auth-flow <FILE>`: Run a login flow and inject the resulting credential.
- `--auth-flow-b <FILE>`: Second login flow for cross-user IDOR checks.
  This is only used when `--active-checks` is enabled.

## Flow File Format

The auth flow is a JSON file with a top-level `steps` array.
Each step is an HTTP request with optional extraction and injection rules.

### Fields

- `url` (string, required): Full URL to request.
- `method` (string, optional): HTTP method, default `POST`.
- `body` (object, optional): JSON request body.
- `headers` (object, optional): Extra headers for this step only.
- `extract` (string, optional): JSONPath to extract the credential value.
- `extract_refresh` (string, optional): JSONPath for refresh token (optional).
- `extract_expires_in` (string, optional): JSONPath for token lifetime in seconds.
- `inject_as` (string or object, optional): How to apply the credential:
  - `"bearer"`: `Authorization: Bearer <value>`
  - `"basic"`: `Authorization: Basic <base64(user:pass)>`
  - `{ "header": "X-Name" }`: `X-Name: <value>`
  - `{ "cookie": "session" }`: `Cookie: session=<value>`

Env var placeholders like `{{SCAN_USER}}` and `{{SCAN_PASS}}` are supported
in `url`, `headers`, and `body` values.

## Examples

See the example files in `docs/examples/`:

- `docs/examples/auth-flow-simple.json`
- `docs/examples/auth-flow-csrf.json`

## Non-JSON Responses

Auth flow steps currently expect JSON responses. Some OAuth2 token endpoints
return `application/x-www-form-urlencoded`, which is not supported. If you need
to use such an endpoint, wrap it in a small proxy/adapter that converts the
response to JSON.

## Multi-Cookie Flows

If a login response sets multiple cookies (for example `session_id` and
`csrf_token`) and both are required in subsequent requests, only one can be
extracted and injected via `extract` + `inject_as`. Any additional cookies
must be provided via `--cookies` on the CLI.
