# Contributing

Thanks for helping improve `safe-bundle`.

This project handles sensitive text by design. The main contribution rule is:
never put live secrets, customer logs, private support bundles, or copied
production credentials into issues, tests, fixtures, examples, or docs.

## Development

Run the full local gate before opening a pull request:

```sh
cargo fmt -- --check
cargo test --locked
cargo clippy --all-targets --locked -- -D warnings
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\ci-smoke.ps1
```

On systems with PowerShell Core:

```sh
pwsh ./scripts/ci-smoke.ps1
```

Package verification:

```sh
cargo +1.85.0 check --locked
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\dependency-policy.ps1
cargo package --locked
```

## Detector Changes

Detector changes should include:

- A detector id that is stable, lowercase, and specific.
- A class and confidence that match the sensitivity of the finding.
- A test proving the detector catches the intended shape.
- A fixture or smoke assertion when the behavior should be visible through the
  CLI.
- A negative or overlap case when the regex could collide with an existing
  detector.

Keep provider-looking test strings synthetic. When a realistic shape is needed
in Rust tests, build it from separate string fragments so repository secret
scanning does not see a full token literal in source.

See [Detector Contribution Guide](docs/DETECTOR_GUIDE.md) for the golden corpus
format, fixture requirements, false-positive expectations, and custom-detector
guidance.

## Public Metadata Contract

Public outputs must never include raw sensitive values:

- Bundle `redactions.jsonl`.
- Bundle `manifest.json`.
- Bundle `summary.md`.
- Bundle `skipped.jsonl`.
- `scrub --events` output.
- CLI text, JSON, or Markdown summaries.

Private receipts may include source spans and raw-value hashes, but not raw
values.

## Structured Formats

When changing redaction or placeholder behavior, preserve the invariant that
valid JSON, JSONL, TOML, YAML, and env-like inputs remain valid after redaction
or fail before output is produced.

## Commit Scope

Keep changes focused. Detector, format-preservation, archive, and CLI UX changes
are easier to review when they land separately.
