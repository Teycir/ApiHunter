---
author: teycir ben soltane
email: teycir@pxdmail.net
website: teycirbensoltane.tn
last_updated: 2026-03-19
tags: [operations, canary, rollback, monitoring, production, runbook]
category: Operations Runbook
---

# Operations Runbook

This runbook defines a safe production rollout path for ApiHunter and the minimum monitoring/rollback controls expected for production use.

## Preconditions

- Explicit written authorization for all target scopes.
- `SECURITY.md` disclosure policy is published.
- Release artifacts are available with checksums/signatures/SBOM.
- CI gates are green (`fmt`, `clippy -D warnings`, tests, dependency audit).
- Branch protection is enabled for the default branch with required PR review and CODEOWNERS enforcement.
- Release hardening smoke workflow is green (`Actions -> release-smoke -> workflow_dispatch`) before first production tag.

## Canary Rollout Strategy

Use progressive rollout, not full-scope activation on day one.

1. Stage 0: passive baseline
- Run passive-only scan on approved targets.
- Keep `--active-checks` disabled.
- Save structured output for comparison.

```bash
./target/release/apihunter \
  --urls targets/prod-approved.txt \
  --format pretty \
  --output run-passive.json \
  --summary
```

2. Stage 1: limited canary active checks
- Enable `--active-checks` on a small subset (5-10% of approved targets).
- Use conservative performance settings and disable discovery fan-out.

```bash
./target/release/apihunter \
  --urls targets/prod-canary.txt \
  --active-checks \
  --no-discovery \
  --concurrency 4 \
  --delay-ms 250 \
  --retries 1 \
  --timeout-secs 8 \
  --format pretty \
  --output run-canary.json \
  --summary
```

3. Stage 2: broaden to 25-50%
- Increase target set only if Stage 1 remains within alert thresholds.
- Keep conservative timing and review new finding quality.

4. Stage 3: full rollout
- Move to full approved scope only after two consecutive clean canary runs.
- Keep passive-first posture for new environments.

## Rollback Triggers

Roll back immediately to passive mode (or stop runs) if any of the following is true:

- Repeated operator-impact signals:
  - target owner reports service degradation, blocking, or false-positive flood.
- Error pressure exceeds threshold:
  - scanner errors on more than 5% of scanned URLs in a run.
- Retry pressure exceeds threshold:
  - `http_retries / http_requests > 0.35` for a run.
- High-severity noise burst:
  - unexpected spike in new `HIGH`/`CRITICAL` findings that cannot be triaged quickly.

Rollback action:
- disable active checks (`--active-checks` off),
- reduce concurrency (`--concurrency 2-4`) and increase delay,
- rerun passive baseline to confirm stability.

## Monitoring and Alerts

Track these metrics per run:

- `meta.runtime_metrics.http_requests`
- `meta.runtime_metrics.http_retries`
- `meta.runtime_metrics.scanner_findings`
- `meta.runtime_metrics.scanner_errors`
- top-level `scanned`, `skipped`, and `errors` counts

Suggested thresholds:

- Warning:
  - retry ratio (`http_retries/http_requests`) > 0.20
  - scanner errors > 2% of scanned URLs
- Critical:
  - retry ratio > 0.35
  - scanner errors > 5% of scanned URLs
  - sustained connectivity failures across multiple scanners

## Post-Run Triage Discipline

- Triage all `HIGH`/`CRITICAL` findings before expanding rollout scope.
- Maintain a baseline file (`--baseline`) for “new finding only” comparisons.
- Capture scanner-specific false positives and tune rollout policy before scaling active checks.

## Incident Notes Template

For every rollback event, record:

- run timestamp and target subset,
- command/options used,
- metric values at trigger point,
- impacted scanners,
- rollback action taken,
- follow-up tuning decisions.
