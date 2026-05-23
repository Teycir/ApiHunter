# Triage Regression Suite

## Quick Start

```bash
# Run full regression suite (200+ targets, ~3-5 minutes)
./scripts/run-triage-regression.sh

# Run with custom targets
./scripts/run-triage-regression.sh --custom targets/my-list.txt

# Run specific test
cargo test --test triage_regression triage_regression_completeness -- --ignored --nocapture
```

## What It Tests

✅ **Completeness**: Every target produces exactly one entry  
✅ **Sorting**: Entries sorted by raw_score descending  
✅ **Scoring**: Distribution across severity levels and score buckets  
✅ **Coverage**: >70% port coverage, >80% ASN coverage  
✅ **Error Handling**: No silent failures  
✅ **Known Targets**: Google DNS has port 53, Cloudflare has AS13335  

## Target List

201 stable infrastructure IPs:
- DNS servers (Google, Cloudflare, Quad9, OpenDNS, root servers)
- NTP servers (Google, Cloudflare, NIST)
- CDN edge nodes (Cloudflare, Akamai, Fastly)
- Cloud providers (AWS, Azure, GCP, DO, Linode, Vultr)
- Major ISPs and backbone providers
- IX points (DE-CIX, AMS-IX, LINX)

All targets are publicly documented and explicitly available for scanning.

## When to Run

- Before releases
- After triage engine changes
- Weekly/monthly for drift detection
- When investigating probe regressions

## Expected Output

```
=== SUMMARY ===
elapsed: 180000ms
total entries: 201
errors: 5

=== SCORING DISTRIBUTION ===
0-20:   45 entries
21-40:  78 entries
41-60:  52 entries
61-80:  18 entries
81-100: 8 entries

=== COVERAGE METRICS ===
port coverage: 85.2%
ASN coverage: 92.1%
```

See [docs/triage-regression.md](../docs/triage-regression.md) for full documentation.
