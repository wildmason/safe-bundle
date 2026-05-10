# Changelog

All notable changes to `safe-bundle` are documented here.

The project follows semantic versioning before 1.0 with the usual pre-1.0
caveat: CLI and bundle schemas may change when needed, but breaking changes
should be called out explicitly.

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
