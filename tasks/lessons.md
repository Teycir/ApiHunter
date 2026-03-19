# Lessons Learned

## 2026-03-18
- User preference: keep session/cookie input format singular and explicit; avoid multiple equivalent flags.
- Rule: when a user asks for one format, remove alternate CLI aliases and parser modes instead of documenting all variants.
- Rule: keep README/HOWTO/config docs synchronized immediately after CLI surface changes to prevent usage confusion.
- Rule: when external tooling (like Docker daemon) is temporarily unavailable, retry promptly once user confirms readiness and continue validation without delay.
- User correction pattern: mass-assignment signals should be explicitly confirmed, not inferred from reflection alone.
- Rule: for active-check findings that imply persisted state change, require a baseline-vs-confirm read comparison before raising high-severity confirmation checks.
- User preference: validate new scanner behavior against real public targets, not only mocks.
- Rule: after adding/changing active checks, run at least one low-impact real-target validation pass (`--no-discovery`) and log the exact command and outcomes.
- User preference: all test execution must run outside sandbox.
- Rule: always run `cargo test` (full or targeted) with escalation/outside sandbox, even if sandbox execution appears possible.
- Rule scope: this preference is global across repos; enforce it via `/home/teycir/.codex/AGENTS.md` so all projects inherit it.

## 2026-03-19
- User preference: CVE checks must come from external template files, not embedded fallback catalogs.
- Rule: keep CVE scanner loading template-only (`assets/cve_templates/*.toml` + optional extra dirs) and avoid runtime fallback to bundled single-file catalogs.
- User preference: keep expanding CVE coverage from real template sources, not a tiny fixed starter set.
- Rule: when CVE catalog breadth is requested, use Exa to source upstream template/advisory references and add only checks that fit ApiHunter's low-impact execution model.
- User preference: every CVE template should be proven with true-positive validation, not only mock tests.
- Rule: maintain and use in-repo regression target lists for CVE true-positive and negative runs (`targets/cve-regression-vulhub-local.txt`, `targets/cve-regression-real-public.txt`).
- Rule: for context-gated CVE templates, seed scans with context-bearing URLs (for example `/actuator`, `/nacos`, `/apisix/admin`) or findings may be skipped.
