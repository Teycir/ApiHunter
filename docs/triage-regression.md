# Triage Mode Regression Testing

## Overview

The triage regression suite validates that the triage engine produces consistent, complete results against a curated list of 200 stable infrastructure IPs. This suite is designed for non-regression testing — ensuring that changes to the triage engine don't break core functionality.

## Target Selection

The regression target list (`targets/triage-regression-200.txt`) contains 200 stable, well-known infrastructure IPs:

- **DNS Servers**: Google (8.8.8.8), Cloudflare (1.1.1.1), Quad9, OpenDNS, etc.
- **Root DNS Servers**: All 13 root DNS servers
- **NTP Servers**: Google, Cloudflare, NIST, US Naval Observatory
- **CDN Edge Nodes**: Cloudflare, Akamai, Fastly
- **Major Cloud Providers**: AWS, Azure, GCP, DigitalOcean, Linode, Vultr
- **Public Institutions**: MIT, Stanford, Berkeley, CMU
- **Open Source Infrastructure**: GitHub, GitLab, Internet Archive
- **Major ISPs**: Comcast, AT&T, Verizon, CenturyLink
- **IX Points**: DE-CIX, AMS-IX, LINX

All targets are:
- Publicly documented
- Stable (long-lived, not ephemeral)
- Explicitly available for scanning/testing
- Well-indexed in Shodan InternetDB and ipinfo.io

## Test Coverage

The regression suite includes 6 test cases:

### 1. `triage_regression_completeness`
Validates structural completeness:
- Every target produces exactly one entry
- No duplicate targets
- Entries sorted by raw_score descending
- Total count matches input count

### 2. `triage_regression_scoring_distribution`
Validates scoring behavior:
- Score distribution across buckets (0-20, 21-40, 41-60, 61-80, 81-100)
- Severity distribution (info/low/medium/high/critical)
- Signal coverage (ports, CVEs, ASN, country)
- Coverage metrics (>70% port coverage, >80% ASN coverage expected)

### 3. `triage_regression_error_handling`
Validates error handling:
- Errors never silent (appear in result.errors or entry.signals)
- Signal type breakdown
- Failure rate analysis

### 4. `triage_regression_top_scorers`
Validates ranking:
- Top 20 entries by score
- Score/severity/vulnerability distribution
- Port and CVE details for high-risk targets

### 5. `triage_regression_known_dns_servers`
Validates specific known targets:
- Google DNS (8.8.8.8) has port 53
- Cloudflare DNS (1.1.1.1) has AS13335
- Root DNS servers have port 53

## Running the Suite

### Quick Run
```bash
./scripts/run-triage-regression.sh
```

### Custom Target List
```bash
./scripts/run-triage-regression.sh --custom targets/my-list.txt
```

### Manual Invocation
```bash
# Run all regression tests
cargo test --test triage_regression -- --ignored --nocapture

# Run specific test
cargo test --test triage_regression triage_regression_completeness -- --ignored --nocapture

# Override target file
APIHUNTER_TRIAGE_REGRESSION_FILE=targets/my-list.txt \
  cargo test --test triage_regression -- --ignored --nocapture
```

## Expected Runtime

- **200 targets** with concurrency=20, timeout=10s
- **Expected duration**: 2-5 minutes (depends on network latency and probe response times)
- **Probe coverage**: InternetDB (ports/CVEs) + ipinfo.io (ASN/country) + RDAP (registration)

## Interpreting Results

### Success Criteria
- All 200 targets produce entries
- No panics or engine-level failures
- Entries sorted correctly
- High signal coverage (>70% ports, >80% ASN)
- Errors recorded explicitly (not silent)

### Expected Failures
Some probe failures are normal:
- **InternetDB timeouts**: IP not indexed or Shodan rate-limited
- **ipinfo.io timeouts**: Rate-limited or network issues
- **RDAP timeouts**: WHOIS server slow or unavailable

These appear as signals in entry.signals, not as missing entries.

### Regression Indicators
Watch for:
- **Completeness drop**: Fewer than 200 entries (engine bug)
- **Coverage drop**: <50% port coverage (probe regression)
- **Sorting errors**: Entries not sorted by raw_score
- **Silent failures**: Errors not recorded in result.errors or entry.signals

## Integration with CI/CD

The regression suite is **not** run in CI by default (marked `#[ignore]`). Run manually:
- Before releases
- After triage engine changes
- Weekly/monthly for drift detection

To add to CI:
```yaml
- name: Triage Regression
  run: cargo test --test triage_regression -- --ignored --nocapture
  timeout-minutes: 10
```

## Baseline Snapshots

For drift detection, save baseline snapshots:

```bash
# Generate baseline
cargo test --test triage_regression triage_regression_scoring_distribution \
  -- --ignored --nocapture > baseline-$(date +%Y%m%d).txt

# Compare against baseline
diff baseline-20260523.txt <(cargo test --test triage_regression \
  triage_regression_scoring_distribution -- --ignored --nocapture)
```

## Troubleshooting

### All probes timing out
- Check network connectivity
- Verify DNS resolution
- Check firewall rules
- Try increasing timeout: edit `triage_config()` in `tests/triage_regression.rs`

### Low coverage (<50%)
- Shodan InternetDB may be rate-limiting
- ipinfo.io may be rate-limiting
- Try running with lower concurrency
- Wait 1 hour and retry

### Specific target failures
- Check if target IP changed (infrastructure migration)
- Verify target still publicly accessible
- Check Shodan InternetDB manually: `https://internetdb.shodan.io/<ip>`

## Maintenance

### Adding Targets
Edit `targets/triage-regression-200.txt`:
- Add stable, well-known IPs only
- Include comment explaining what the IP is
- Verify IP is publicly documented
- Test manually before committing

### Removing Targets
Remove IPs that:
- Are no longer stable (frequent changes)
- Are no longer publicly accessible
- Cause consistent probe failures

### Updating Assertions
If infrastructure changes (e.g., Google DNS moves to new ASN):
- Update assertions in `triage_regression_known_dns_servers`
- Document change in commit message
- Verify change is real (not a probe bug)

## Related Documentation

- [Triage Mode Guide](triage.md)
- [Testing Strategy](testing.md)
- [Operations Runbook](operations.md)
