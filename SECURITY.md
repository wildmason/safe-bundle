# Security Policy

`safe-bundle` is a local-first developer safety tool. It is designed to reduce
the chance that support bundles, issue attachments, or AI prompts include
secrets or local identity details.

It is not a legal de-identification system and it cannot guarantee that
arbitrary free text contains no sensitive data.

## Supported Versions

Until the project reaches 1.0, security fixes target the latest released
version and `main`.

| Version | Supported |
| --- | --- |
| 0.1.x | Yes |

## Reporting a Vulnerability

Do not open a public issue containing a live secret, proprietary log, private
support bundle, or unredacted customer data.

Preferred channels:

- Use GitHub private vulnerability reporting for this repository, if enabled.
- Otherwise email `security@wildmason.dev` with a minimal reproduction and no
  live credentials.

Useful reports include:

- A detector miss for a common credential shape.
- A case where public `redactions.jsonl`, `skipped.jsonl`, `manifest.json`, or
  `scrub --events` output includes raw sensitive values.
- A bundle path traversal, archive extraction, or checksum integrity issue.
- A structured-file case where redaction produces invalid JSON, JSONL, TOML,
  YAML, or env output without failing.

## Response Goals

- Acknowledge credible reports within 7 days.
- Fix high-impact leakage or archive-safety issues before the next routine
  release.
- Credit reporters in release notes when they want public credit.
