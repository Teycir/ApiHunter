# Enrich Mode

Enrich Mode adds external threat intelligence context to findings from Quick Mode.
It queries free, unauthenticated APIs to add port exposure, CVE associations,
ASN/hosting flags, and domain registration metadata.

## Problem It Solves

Quick Mode finds vulnerabilities fast (1000 targets in 0.14s) but lacks context:
- Which targets have exposed SSH/RDP?
- Are there known CVEs for this host?
- Is this a hosting provider or corporate network?
- How old is this domain?

Enrich Mode answers these questions without slowing down the initial scan.

## How It Works

For each finding from Quick Mode, Enrich fires **two lightweight HTTP probes in parallel**:

| Probe | Endpoint | Auth | What it returns |
|-------|----------|------|-----------------|
| InternetDB | `https://internetdb.shodan.io/{ip}` | none | Open ports, CVE IDs, tags (honeypot/scanner), CPEs |
| ipinfo.io | `https://ipinfo.io/{ip}/json` | none (free tier) | ASN, org, country, anycast/hosting flag |

For domain targets a DNS resolution step (DoH via Cloudflare) runs first to
obtain the IP before the two probes. RDAP is queried for domain age, expiry,
and nameserver presence.

All three sources are **free, unauthenticated, and sub-100 ms** under normal
conditions.

## Scoring Model

Scores are computed locally from probe responses using the same additive model
ported from [SeekYou](https://github.com/Teycir/SeekYou). The score is a
number from 0–100; higher means more interesting for a security scan.

```
ATTACK SURFACE (open ports)              max 15
  High-risk port (22,23,445,3389,…)    4 pts each (cap 12)
  Any other open port                  1 pt each  (cap  5)

CVE EXPOSURE                             max 25
  CVSS 9–10 critical                  15 pts/CVE
  CVSS 7–8.9 high                      8 pts/CVE
  CVSS 4–6.9 medium                    4 pts/CVE
  CVSS < 4 low/none                    1 pt/CVE

NETWORK FLAGS                            max 10
  Hosting/anycast ASN                  3 pts
  Known honeypot tag (InternetDB)      5 pts
  Scanner tag (InternetDB)             3 pts

DOMAIN REGISTRATION (domain targets)    max 15
  Domain < 30 days old                15 pts
  Domain expired                      10 pts
  Privacy-protected registrant         5 pts
  No nameservers                       8 pts
```

**Severity bands**

| Score | Band |
|-------|------|
| 0–24 | LOW |
| 25–49 | MEDIUM |
| 50–74 | HIGH |
| 75–100 | CRITICAL |

## Signals Output

Each triage entry exposes a `signals` list — a human-readable explanation of
what drove the score, for example:

```
port 22 open, port 3306 open, CVE-2021-44228 (CRITICAL), hosting ASN
```

This lets you triage by reading the signals column without opening every result.

## Speed Expectations

Two parallel probes per target, no discovery, no scanner pipeline:

| Targets | Concurrency | Expected time |
|---------|-------------|---------------|
| 500 | 50 | ~30 s |
| 2 000 | 100 | ~1–2 min |
| 5 000 | 200 | ~3–5 min |

Times assume average probe latency of 80–150 ms. Slow/unreachable hosts time
out at 5 s (configurable) and are marked with `score: 0, severity: LOW,
signals: ["timeout"]`.

## Output Format

Triage returns a ranked list sorted by score descending. Each entry:

```json
{
  "target": "api.example.com",
  "resolved_ip": "93.184.216.34",
  "score": 82,
  "severity": "CRITICAL",
  "signals": ["port 443 open", "port 22 open", "CVE-2021-44228 (CRITICAL)", "hosting ASN"],
  "ports": [22, 80, 443],
  "cve_ids": ["CVE-2021-44228"],
  "asn": "AS15169",
  "country": "US",
  "domain_age_days": null,
  "response_ms": 94
}
```

## Desktop Usage

In the ApiHunter desktop app, Triage is a separate collapsible panel — **Triage
Scan** — below the Full Scan panel. It does not share state with Full Scan.

1. Enter targets (same format as Full Scan — one per line, comma, or semicolon
   separated). There is no target cap for triage.
2. Set **Concurrency** (default 100) and **Timeout** (default 5 s).
3. Click **Run Triage**.
4. Results appear as a ranked table with score badge, severity chip, and
   signals summary.
5. Use **Promote to Full Scan** per row or **Promote Top N** to push selected
   targets into the Full Scan target textarea for deep scanning.

### Promote Top N

The **Promote Top N** control lets you define a score threshold or a count
cutoff. Clicking it merges the selected targets into the Full Scan textarea
(deduped). You can then apply a Full Scan preset and run immediately.

## CLI Usage

```bash
# Enrich a findings file produced by a previous scan
apihunter enrich --findings findings.ndjson --output enriched.ndjson

# Meta lines ({"type":"meta",...}) are automatically skipped
# No pre-filtering needed — enrich handles full NDJSON exports directly

# Use a higher concurrency for large findings files
apihunter enrich --findings findings.ndjson --concurrency 100 --output enriched.ndjson

# Emit only enriched output (no console progress)
apihunter enrich --findings findings.ndjson --quiet --output enriched.ndjson

# Promote hosts scoring ≥ 50 to a target file for a subsequent deep scan
apihunter enrich --findings findings.ndjson \
  --promote-to hot-targets.txt --promote-min-score 50

# Full pipeline: mass sweep → enrich → deep scan
apihunter --urls all.txt --preset mass --output findings.ndjson
apihunter enrich --findings findings.ndjson --promote-to hot.txt --promote-min-score 25
apihunter --urls hot.txt --preset deep --active-checks --format sarif
```

### Enrich CLI Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--findings` | required | Path to NDJSON findings file from a previous scan |
| `--concurrency` | `50` | Parallel probe tasks (one probe per unique host) |
| `--timeout-secs` | `5` | Per-probe timeout |
| `--format` | `ndjson` | `ndjson` or `json` |
| `--output` | stdout | Write enriched output to file |
| `--promote-to` | none | Write qualifying host URLs to a file for `--urls` input |
| `--promote-min-score` | `0` | Minimum threat-intel score for promotion (0–100) |
| `--quiet` | off | Suppress progress messages on stderr |

---

## Triage CLI Usage

```bash
# Triage a file of targets, output JSON, sort by score
apihunter triage --urls targets/large-list.txt --format json --output triage.json

# Pipe targets from another tool
cat targets.txt | apihunter triage --stdin --concurrency 200

# Only show HIGH and CRITICAL targets
apihunter triage --urls targets/large-list.txt --min-score 50

# Promote top 50 to a new file for full scanning
apihunter triage --urls targets/large-list.txt --top 50 --promote-to promoted.txt
```

### Triage CLI Flags (for `apihunter triage`)

| Flag | Default | Description |
|------|---------|-------------|
| `--urls` | required* | Newline-delimited target file |
| `--stdin` | off | Read targets from stdin |
| `--concurrency` | `100` | Parallel probes |
| `--timeout-secs` | `5` | Per-probe timeout |
| `--min-score` | `0` | Only emit entries at or above this score |
| `--top` | `0` (all) | Emit only the top N entries by score |
| `--promote-to` | none | Write promoted targets to a file for `--urls` input |
| `--format` | `pretty` | `pretty`, `json`, or `ndjson` |
| `--output` | stdout | Write triage output to file |

*`--urls` or `--stdin` required.

## Implementation Notes

The triage engine lives in `src/triage/` and is fully independent of the
main scanner pipeline in `src/runner.rs`. It shares the HTTP client
infrastructure (`HttpClient`, timeouts, retries) but uses its own concurrency
pool and does not invoke any scanner modules.

Source logic is translated from [SeekYou](https://github.com/Teycir/SeekYou)
(`lib/risk.ts`, `lib/normalize.ts`, `worker/sources/internetdb.ts`,
`worker/sources/ipapi.ts`, `worker/sources/rdap.ts`) into native Rust with
no network dependency on SeekYou itself.

```
src/triage/
  mod.rs          — public surface, TriageResult, run_triage()
  risk.rs         — scoring model (ported from SeekYou lib/risk.ts)
  normalize.rs    — signal normalization (ported from lib/normalize.ts)
  types.rs        — TriageEntry, InternetDBResult, IPAPIResult, RDAPResult
  resolver.rs     — domain → IP via DoH (Cloudflare 1.1.1.1)
  sources/
    mod.rs
    internetdb.rs — Shodan InternetDB probe
    ipapi.rs      — ipinfo.io geo/ASN probe
    rdap.rs       — IANA RDAP domain registration probe
```

## What Triage Does Not Do

- Does not send any scanner payloads (CORS probes, JWT extraction, GraphQL
  introspection, CVE template matching, etc.)
- Does not perform endpoint discovery (no robots.txt, sitemap, or JS parsing)
- Does not consult abuse.ch, URLhaus, ThreatFox, or any threat intel feeds
  (those are Layer 2 enrichment — available post-triage on promoted targets
  via a future `--enrich` flag)
- Does not write to `~/Documents/ApiHunterReports` (triage output is
  stdout/file only)
- Does not affect `--fail-on` exit codes (triage has its own exit path)

## Relationship to Quick Mode

Quick Mode and Enrich are designed to be used in sequence:

```
5 000 targets
    │
    ▼
apihunter --urls all-targets.txt --triage --output findings.ndjson
    │ (0.7 seconds)
    ▼ findings.ndjson (targets with HIGH/CRITICAL findings)
    │
    ▼
apihunter enrich --findings findings.ndjson --output enriched.ndjson
    │ (30-60 seconds for context)
    ▼ enriched.ndjson (findings + port/CVE/ASN/domain context)
    │
    ▼
apihunter --urls hot-targets.txt --active-checks --format sarif
```

Enrich does not replace scanning. It adds context to help prioritize which
findings deserve active exploitation attempts.
