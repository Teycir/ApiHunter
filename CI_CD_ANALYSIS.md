# Global CI/CD Rule

All projects must run the full verification suite before CI/CD is considered clean.  
If any check fails or is skipped, CI/CD is **not** clean.

## Required Checks

- Format (`rustfmt`)
- Linting (`clippy`)
- Tests (all test suites)
- Build (clean compile)

## CI/CD Verification Summary (Template)

| Check | Status |
|---|---|
| Format (rustfmt) | ✅ PASSED |
| Linting (clippy) | ✅ PASSED - 0 warnings |
| Tests | ✅ PASSED - 79 tests |
| Build | ✅ PASSED - Clean compile |

