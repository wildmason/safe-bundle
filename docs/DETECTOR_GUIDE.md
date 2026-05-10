# Detector Contribution Guide

Detector changes affect what users trust before sharing diagnostics. Keep them
small, fixture-backed, and reviewable.

## Built-In Detector Requirements

Every built-in detector change needs:

- a stable lowercase id, such as `provider-api-key`;
- a redaction class from `RedactionClass`;
- a confidence value that matches the detector's precision;
- a short user-facing reason;
- a Rust unit test when the behavior is narrow or overlap-sensitive;
- a golden corpus case when users should depend on the behavior through the
  public redaction pipeline;
- a false-positive case when the pattern could match ordinary configuration.

Use synthetic values only. Never copy a real token into a fixture, commit,
issue, or pull request.

## Golden Corpus Format

Add corpus coverage in `fixtures/golden/redaction-corpus.toml`.

Positive cases use:

```toml
[[cases]]
id = "provider-example"
profile = "public-issue"
format = "env"
min_redactions = 1
expected_detectors = ["provider-api-key"]
expected_classes = ["secret.cloud_credential"]
must_redact = ["fixture_provider_token_abcdefghijklmnopqrstuvwxyz"]
must_keep = ["APP_ENV=development"]
input = '''
APP_ENV=development
PROVIDER_API_KEY=fixture_provider_token_abcdefghijklmnopqrstuvwxyz
'''
```

False-positive cases use:

```toml
[[false_positive_cases]]
id = "provider-benign-config"
profile = "public-issue"
format = "env"
must_keep = ["PROVIDER_TOKEN_MODE=disabled"]
input = '''
PROVIDER_TOKEN_MODE=disabled
'''
```

Golden cases assert that:

- at least `min_redactions` findings are emitted;
- listed detectors and classes appear;
- `must_redact` values disappear from redacted output;
- `must_redact` values do not appear in public event JSON;
- `must_keep` values remain;
- structured formats remain parseable when the source is valid.

## Regex Guidelines

Prefer precise provider-specific shapes over broad catch-all regexes. If a
detector matches key/value assignments, capture only the value and use
`with_context_key_group` so public metadata can explain which key matched
without exposing the value.

When a detector can overlap with generic secret detection, set a higher
specificity so the more useful detector id wins. Avoid patterns that match
common booleans, counts, policy names, or status words.

## Custom Detector First

If the shape is only useful for one repository, document it as a
`.safe-bundle.toml` custom detector instead of adding it to the built-in list:

```toml
[[custom_detectors]]
id = "ticket-token"
pattern = "ticket_[A-Za-z0-9_]{12,}"
class = "secret.api_key"
confidence = "high"
reason = "ticket fixture token"
```

Built-ins should cover common developer support artifacts or widely used
provider credentials.

## Local Gate

Run:

```sh
cargo fmt -- --check
cargo test --locked
cargo clippy --all-targets --locked -- -D warnings
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\ci-smoke.ps1
```

For release-impacting detector changes, also run:

```sh
cargo +1.85.0 check --locked
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\dependency-policy.ps1
cargo package --locked
```
