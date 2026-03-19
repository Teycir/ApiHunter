# Contributing to ApiHunter

Thanks for contributing.

## Development Setup

1. Install Rust stable (1.76+ recommended).
2. Clone the repository and build:

```bash
git clone https://github.com/Teycir/ApiHunter
cd ApiHunter
cargo build
```

## Code Style

- Run formatting before opening a PR:

```bash
cargo fmt
```

- Keep changes focused and minimal.
- Prefer clear names and small, testable units.
- Avoid introducing unrelated refactors in the same PR.

## Testing

- Run the full test suite locally:

```bash
cargo test
```

- Keep all tests in the `tests/` directory.
- Do not add test code inside production source files.

## Documentation

- Update `README.md`, `HOWTO.md`, and `docs/` when CLI flags, defaults, or behavior change.
- Add usage examples for new features when relevant.

## Pull Request Checklist

1. Code builds with `cargo build`.
2. Formatting passes with `cargo fmt`.
3. Tests pass with `cargo test`.
4. Documentation is updated for user-facing changes.
5. Changelog entry is added when needed.
6. For protected branches, required CODEOWNERS review is obtained.

## Bug Reports and Feature Requests

When opening an issue, include:

- ApiHunter version (`./target/debug/api-scanner --version` or release binary version)
- Command used
- Expected behavior
- Actual behavior
- Logs or sample output (redacted if sensitive)
