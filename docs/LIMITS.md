# Guarantees and Limits

`safe-bundle` is a local safety tool for developer diagnostics. It reduces the
chance that you share credentials, local identity, private host details, or
common provider tokens by accident.

It is not a legal anonymization tool, a data-loss-prevention platform, or a
guarantee that an artifact is safe to publish without review.

## What You Can Rely On

- Processing is local. The CLI does not call a hosted service or send telemetry.
- Public redaction metadata does not include raw matched values.
- Private receipts store source spans and raw-value hashes, not raw values.
- Bundles contain redacted files, manifests, summaries, skipped-file records,
  public redaction events, checksums, and a README. They do not contain original
  input files.
- `inspect --verify` checks required entries, schema version, checksums, file
  hashes, redaction event parseability, redaction counts, and logical bundle
  hash.
- Valid JSON, JSONL, TOML, YAML, and env-like inputs are checked after redaction
  so structure-breaking replacements fail.
- Binary, non-UTF-8, and over-limit files are skipped and listed for review.

## What You Must Still Review

- Business-sensitive prose that has no recognizable secret shape.
- Proprietary source code, diffs, algorithms, customer names, issue details, and
  screenshots.
- New token formats that are not covered by built-in detectors or repository
  custom detectors.
- Skipped files. A skipped file was not redacted.
- Values preserved by allowlist rules or path profile overrides.
- Redacted output before posting it publicly.

## Residual Risk

The main risk is a false negative: a sensitive value may not match any detector.
Use stricter profiles, repository custom detectors, and human review for public
publication.

The second risk is over-redaction: useful diagnostic detail may be replaced by a
placeholder. Use the `support` or `internal` profile only when the recipient and
channel are trusted, and keep private receipts local for correlation.

The third risk is context leakage: a file path, error message, or retained line
may reveal enough information to matter even when explicit secrets are removed.
Review the final bundle as if you were about to paste it into the destination
channel by hand.

## Practical Rule

Use `safe-bundle` before sharing. Then inspect what it produced. If the redacted
artifact still feels too revealing, do not share it until you remove the file,
add a detector, switch profiles, or rewrite the example.
