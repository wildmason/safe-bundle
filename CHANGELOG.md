# Changelog

All notable changes to `safe-bundle` are documented here.

The project follows semantic versioning before 1.0 with the usual pre-1.0
caveat: CLI and bundle schemas may change when needed, but breaking changes
should be called out explicitly.

## Unreleased

### Added

- PowerShell installer for GitHub Release binary archives.
- Release verification script for downloaded checksums and GitHub artifact
  attestations.
- Distribution documentation covering GitHub Releases, crates.io, and
  verification expectations.
- CI smoke coverage for release helper script syntax.

## 1.0.0 - 2026-05-10

Stable local safety contract release.

### Added

- Golden detector corpus under `fixtures/golden/`, with integration tests that
  assert expected redactions, preserved benign config values, structured-output
  validity, and no raw fixture values in public event JSON.
- `.safe-bundle.toml` repository policy loading, including explicit
  `--config`, `--no-config`, allowlist literals/regexes, custom detectors, and
  first-match per-path profile overrides.
- `inspect --verify` for bundle schema, checksum, redaction JSONL, and logical
  bundle-hash validation.
- Logical golden compatibility test coverage for the schema-v1 bundle layout
  and manifest contract.
- `scrub --check` for CI-friendly redaction checks.
- `scrub --sarif <path>` for GitHub code-scanning uploads.
- Composite GitHub Action wrapper in `action.yml`.
- `docs/AUTOMATION.md` with GitHub Actions, pre-commit, and git hook
  examples.
- MSRV CI for Rust 1.85 and a local dependency policy script.
- Release workflow smoke tests for packaged binary archives.
- Property-style hardening tests for redaction ordering, archive path
  sanitization, and structured format preservation.
- User-facing workflow docs for public issues, support handoff, LLM prompt
  cleanup, internal triage, and CI preflight.
- Detector contribution guide with golden corpus and false-positive fixture
  requirements.
- User-facing guarantees and limits documentation.
- Release-candidate checklist covering accuracy, public artifact safety, CLI,
  config, bundle, hardening, and publication gates.
- CLI contract tests for the 1.0 command surface.
- GitHub artifact attestations for release crate and binary archives.
- Provider detector coverage for AWS secret/session tokens, escaped PEM private
  keys in JSON strings, Stripe webhook secrets, SendGrid, Datadog, Netlify,
  Vercel, Postmark, Sentry, Supabase service-role keys, and Twilio auth tokens.
- `docs/CONFIG.md` documenting repository policy configuration.
- `docs/BUNDLE_FORMAT.md` documenting the schema-v1 bundle contract.
- `docs/ROADMAP.md` documenting the 0.2-to-1.0 release ladder.

### Changed

- Generic secret-like key/value detection now avoids common benign config words
  such as `required`, `false`, `active`, and count/policy toggles.
- Archive path sanitization now rejects drive-letter path components even on
  non-Windows platforms.
- Updated direct dependencies: `sha2` 0.11, `toml` 1.1, and `zip` 7.2.

## 0.1.0 - 2026-05-10

Initial public developer-preview release.

### Added

- `scrub` command for stdin and file redaction.
- `bundle` command for creating redacted `.safe-bundle.zip` support archives.
- `inspect` command for validating and summarizing generated bundles.
- `rules list` and `rules test` commands for detector visibility.
- Deterministic placeholders such as `[REDACTED:SECRET.CLOUD_CREDENTIAL:1]`.
- Public redaction event JSONL that excludes raw sensitive values.
- Optional private receipts containing hashes and source spans for sender-side
  correlation.
- Structured validation for JSON, JSONL, TOML, YAML, and env-like files after
  redaction.
- Provider-oriented detector coverage for AWS, GitHub, Stripe, npm, OpenAI,
  Anthropic, Slack, Discord, Fly.io, Resend, Lemon Squeezy, Google API keys,
  and Azure storage account keys.
- `scrub --events <path>` for public finding metadata without creating a
  bundle, including `--dry-run` support for CI/preflight review.
- Cross-platform CI on Ubuntu, macOS, and Windows.
