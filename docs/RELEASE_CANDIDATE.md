# Release Candidate Checklist

This is the `1.0.0` freeze checklist. A release candidate is ready when every
item below is true on `main`.

## Accuracy

- The golden corpus passes.
- Every `must_redact` value disappears from redacted output.
- No `must_redact` value appears in public event JSON.
- Known false-positive fixtures stay unredacted.
- There are no known high-severity false negatives in the committed corpus.

Command:

```sh
cargo test --locked golden
```

## Public Artifact Safety

- `scripts/ci-smoke.ps1` scans public bundle artifacts and `scrub --events`
  outputs for raw fixture leaks.
- `inspect --verify` validates generated bundles.
- SARIF output is public metadata only and does not contain raw matched values.

Command:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\ci-smoke.ps1
```

## CLI Contract

The `scrub`, `bundle`, `inspect`, and `rules` command surface is covered by
`tests/cli_contract.rs`. Any 1.x breaking change to command names or release
candidate flags should be intentional and documented.

Command:

```sh
cargo test --locked cli_contract
```

## Config Contract

The configuration schema is version `1`. Unknown fields are rejected, and `1.x`
releases must keep reading version `1` configs unless a new config version is
introduced.

Canonical docs:

- `docs/CONFIG.md`
- `.safe-bundle.toml` examples in `README.md`

## Bundle Contract

The bundle schema is version `1`. The layout and manifest fields are covered by
the schema-v1 compatibility test, and older schema-v1 redaction events without
new optional fields still parse.

Canonical docs:

- `docs/BUNDLE_FORMAT.md`
- `archive::tests::bundle_schema_v1_layout_matches_golden_contract`
- `archive::tests::schema_v1_redactions_without_source_region_still_parse`

## Hardening

Required local gates:

```sh
cargo fmt -- --check
cargo test --locked
cargo clippy --all-targets --locked -- -D warnings
cargo +1.85.0 check --locked
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\ci-smoke.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\dependency-policy.ps1
cargo package --locked
cargo publish --dry-run --locked
```

Required hosted gates:

- CI green on Ubuntu, macOS, and Windows.
- MSRV job green for Rust 1.85.
- Dependency policy job green.
- Release workflow has packaged archive smoke tests for every binary asset.
- Release workflow generates GitHub artifact attestations for the crate archive
  and binary archives.

## Publication Decision

Official `1.0.0` channels:

- GitHub Releases for signed-by-GitHub workflow provenance, platform archives,
  crate archive, and SHA-256 sidecars.
- Crates.io publication is manual from a clean release commit after
  `cargo publish --dry-run --locked` passes and the GitHub Release workflow is
  green.

Do not publish to crates.io if the GitHub Release workflow fails.
