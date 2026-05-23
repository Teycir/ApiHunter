# Triage Mode

Triage Mode is a high-speed, minimal-overhead scan for volume (1000+ targets).

## Performance

**Real-world bug bounty targets:**
- **1000 targets**: ~4 minutes
- **5000 targets**: ~20 minutes
- **10000 targets**: ~40 minutes

**Fast-responding APIs (test/staging):**
- **1000 targets**: ~0.14 seconds
- **5000 targets**: ~0.7 seconds

## What It Does

Runs only the core scanners without discovery overhead:
- CORS misconfigurations
- CSP policy analysis
- GraphQL introspection
- JWT token analysis
- API security headers

## What It Skips

- Endpoint discovery (robots.txt, sitemap, JS parsing)
- OpenAPI spec probing (15+ paths per target)
- API versioning response-diff probes
- gRPC/Protobuf detection
- Active checks (IDOR, mass assignment, etc.)

## CLI Usage

```bash
# Triage scan 1000 targets (optimized for volume)
apihunter --urls targets.txt \
  --no-discovery \
  --no-openapi \
  --no-api-versioning \
  --no-grpc-protobuf \
  --no-filter \
  --concurrency 200 \
  --delay-ms 10 \
  --timeout-secs 2 \
  --retries 0 \
  --min-severity high

# Or use the triage preset (coming soon)
apihunter --urls targets.txt --triage --min-severity high
```

## Desktop Usage

Select **"Triage"** preset in the scan profile dropdown with these settings:
- Discovery: OFF
- OpenAPI scanner: OFF
- API Versioning scanner: OFF
- gRPC/Protobuf scanner: OFF
- Accessibility filter: OFF
- Concurrency: 200
- Delay: 10ms
- Timeout: 2s
- Retries: 0
- Min Severity: HIGH

## Output

Findings with HIGH/CRITICAL severity only. Use `--min-severity medium` to include MEDIUM findings.

## When to Use

- Initial reconnaissance on large target lists
- CI/CD pre-commit checks
- Continuous monitoring of 1000+ endpoints
- Bug bounty scope validation

## Next Step: Enrich

After Triage Mode identifies targets with findings, use **Enrich Mode** to add context:
- Port exposure (InternetDB)
- CVE associations
- ASN/hosting flags (ipinfo.io)
- Domain registration age (RDAP)

```bash
# Step 1: Triage scan
apihunter --urls all-targets.txt --triage --output findings.ndjson

# Step 2: Enrich findings with context
apihunter enrich --findings findings.ndjson --output enriched.ndjson
```

See [Enrich Mode](enrich.md) for details.
