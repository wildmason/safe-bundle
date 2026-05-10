# Roadmap to 1.0

This roadmap defines the release ladder from the `0.1.0` developer preview to
`1.0.0`.

## 0.2 - Accuracy Harness

Status: shipped on `main`.

Goal: make detector behavior regression-testable before expanding the CLI.

- Maintain a golden corpus under `fixtures/golden/`.
- Require every new detector to add at least one positive fixture and, where
  plausible, one false-positive fixture.
- Keep public event JSON free of raw fixture secrets.
- Keep structured redacted outputs parseable for supported structured formats.
- Expand provider coverage for common developer support bundles.

## 0.3 - Repository Policy

Status: shipped on `main`.

Goal: let users tune behavior per repository without forking the tool.

- Add `.safe-bundle.toml` discovery.
- Support custom detectors.
- Support allowlist rules for known-safe values.
- Support per-path profile overrides.
- Add documented suppression patterns for formats where suppression is safe.

## 0.4 - Bundle Contract

Status: shipped on `main`.

Goal: make `.safe-bundle.zip` a documented, stable interchange format.

- Document `manifest.json`, `redactions.jsonl`, `skipped.jsonl`, and
  `checksums.sha256`.
- Add golden archive compatibility tests.
- Add `inspect --verify` for checksum and schema validation.
- Define schema-version compatibility rules.

## 0.5 - Automation Integrations

Status: shipped on `main`.

Goal: make safe-bundle easy to run in CI and local hooks.

- Add `scrub --check` as a CI-friendly alias for dry-run failure behavior.
- Add SARIF output for code-scanning workflows.
- Add a GitHub Action wrapper.
- Add pre-commit and pre-push examples.

## 0.6 - Hardening

Status: shipped on `main`.

Goal: reduce supply-chain, parser, and platform risk.

- Add MSRV CI for Rust `1.85`.
- Add dependency policy checks.
- Add property/fuzz tests for detector overlap, archive paths, and structure
  preservation.
- Add release-asset install smoke tests for Linux, macOS, and Windows.
- Decide whether release assets need signatures or provenance attestations.

## 0.7 - Documentation and Adoption

Status: shipped on `main`.

Goal: make the tool understandable by someone who did not build it.

- Add "before opening a public issue" workflow documentation.
- Add examples for public GitHub issues, support handoff, LLM prompt cleanup,
  and internal incident triage.
- Add a detector contribution guide with fixture requirements.
- Document clear non-goals and residual risk in user-facing language.

## 0.9 - Release Candidate

Status: shipped on `main`.

Goal: freeze the CLI and bundle schema before `1.0.0`.

- No known high-severity false negatives in the golden corpus.
- No raw fixture secrets in public outputs.
- Stable config format.
- Stable bundle schema.
- Cross-platform CI green.
- Release artifact install smoke green.
- Crates.io publication process decided and tested.

## 1.0 - Stable Local Safety Contract

Status: shipped on `main`.

`1.0.0` means users can install `safe-bundle`, configure it in a repository,
run it locally or in CI, trust the public bundle format, and understand exactly
what the tool does and does not guarantee.
