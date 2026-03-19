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
- User preference: strengthen CVE tests with real data, not only synthetic payloads.
- Rule: capture and replay real payload fixtures from controlled vulnerable targets for CVE scanner regression tests.
- Rule: when requested, use Exa discovery and Fetch retrieval to pin authoritative upstream references into fixture snapshots for parity tests.
- User correction pattern: scanner tests must prove probe execution and payload correctness, not only resulting findings.
- Rule: for active-check tests, assert request path/method specificity and exact probe payload contents, and verify baseline/probe/confirm call ordering when multi-step logic is expected.
- User correction pattern: reflected-field detection must be parser-based and canonicalized, not substring-based.
- Rule: for JSON scanners, unify detection semantics across code paths (reflected vs elevated) using shared key normalization and structured traversal.
- Rule: include variant-key regression tests (`snake_case`, `camelCase`, mixed case) and baseline-failure/reflected-only edge cases whenever detection logic changes.
- User preference: performance improvements must not trade off recall.
- Rule: accept only recall-safe optimizations by default (parse/alloc/traversal efficiencies), and reject heuristic request-skips unless explicitly approved as a detection tradeoff.
- User correction pattern: scanner implementations should favor reusable helpers over repeated inline logic when behavior is shared.
- Rule: extract shared finding creation, response parsing, and confirmation-diff logic into dedicated functions to keep `scan()` readable and easier to maintain.
- User preference: provide safety controls for active checks when requested.
- Rule: when adding invasive-check improvements, include an explicit dry-run path that reports intended actions without sending mutation probes.
