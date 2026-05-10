# safe-bundle Threat Model

This document defines the release-time security posture for `safe-bundle`.

## Goals

- Help developers share useful diagnostics without raw secrets, local identity,
  private hosts, or common provider credentials.
- Produce public artifacts that are safe to inspect before sharing.
- Keep all processing local: no telemetry, hosted service, or network calls.
- Preserve diagnostic structure where possible so redacted output remains
  useful.

## Non-Goals

- Legal anonymization or de-identification. `safe-bundle` reduces developer
  sharing risk, but it does not decide whether data is anonymous under any law.
- Perfect detection of arbitrary sensitive free text. A sentence, stack trace,
  or source snippet can still reveal private information without matching a
  detector.
- Malware scanning. The tool treats input files as data and does not decide
  whether they are safe to run.
- Safe execution or interpretation of input files. The CLI reads text and
  validates supported structured formats; it does not execute artifacts.
- Automatic deletion of original files. Source files stay where they are.

## Assets

- Original input files and stdin.
- Redacted output files.
- Public support bundles.
- Public redaction event JSONL.
- Private receipts.
- File paths and skipped-file metadata.

## Trust Boundaries

- Input files and stdin are untrusted data.
- Redacted outputs and bundle files are intended to be shareable after human
  review.
- Private receipts are sender-side artifacts and should not be shared publicly.
- The CLI process is local and trusted only to the extent that the installed
  binary and dependencies are trusted.

## Primary Risks

### False negatives

A sensitive value may not match any built-in detector. This is the largest
residual risk. Mitigations:

- Provider-specific detectors for common token families.
- Generic key/value secret detection.
- Aggressive `public-issue`, `llm-prompt`, and `strict` profiles.
- `rules list` and `rules test` for visibility.
- README limits that require human review.

### Public metadata leaks

Redaction events, summaries, manifests, skipped-file records, or CLI text could
include raw sensitive values. Mitigations:

- Public events store placeholder, class, spans, detector id, context, and length
  buckets, not raw values.
- Private receipts store raw-value SHA-256 hashes, not raw values.
- Skipped-file and input-root metadata is redacted before bundle write.
- Smoke tests scan public bundle artifacts and `scrub --events` output for
  fixture leaks.

### Broken structured outputs

Replacing sensitive values could corrupt JSON, JSONL, TOML, YAML, or env-like
files. Mitigations:

- Format sniffing.
- Structure-preservation validation after redaction.
- Release smoke coverage for structured fixtures.

### Archive path issues

Bundles could include unsafe paths or ambiguous archive entries. Mitigations:

- Archive paths are normalized from input-relative paths.
- Parent directories, roots, and platform prefixes are rejected.
- Bundle files are written under a `files/` prefix.
- Checksums are recorded for redacted output files.

### Binary and huge-file handling

Binary files or very large files could create misleading output or operational
failures. Mitigations:

- Binary and non-UTF-8 files are skipped.
- File size defaults to 10 MiB and can be configured.
- Skipped files are listed for review.

## Release Checks

Before a release:

- `cargo fmt -- --check`
- `cargo test --locked`
- `cargo clippy --all-targets --locked -- -D warnings`
- `powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\ci-smoke.ps1`
- `cargo package --locked`
- Cross-platform GitHub Actions must pass on Ubuntu, macOS, and Windows.
