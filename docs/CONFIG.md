# Configuration

`safe-bundle` works without configuration. For repository-specific policy,
place `.safe-bundle.toml` in the repository root or pass `--config <path>`.
Discovery walks from the current directory upward. Use `--no-config` to force
built-in behavior.

## Example

```toml
version = 1

[allowlist]
literals = ["ticket_keep_this_value"]
regexes = ["SAFE-[0-9]+"]

[[custom_detectors]]
id = "ticket-token"
pattern = "ticket_[A-Za-z0-9_]{12,}"
class = "secret.api_key"
confidence = "high"
reason = "ticket fixture token"
capture_group = 0

[[path_overrides]]
pattern = "public/**"
profile = "internal"
```

## Allowlist

Allowlist entries skip matching raw values before redaction.

- `literals` match exact detector values.
- `regexes` match detector values, not full files.

Do not use allowlists as a general escape hatch. They are for values known to be
safe to publish, such as stable fixture placeholders or documented fake tokens.

## Custom Detectors

Each `[[custom_detectors]]` entry adds one repository-local detector.

Required fields:

- `id`: unique detector id. It cannot duplicate a built-in detector id.
- `pattern`: Rust `regex` pattern.
- `class`: redaction class such as `secret.api_key` or `identity.contact`.
- `confidence`: `low`, `medium`, or `high`.
- `reason`: short user-facing explanation.

Optional fields:

- `capture_group`: regex capture group to redact. Defaults to `0`.
- `context_key_group`: capture group to expose as public `context.key`.

## Path Overrides

`[[path_overrides]]` applies the first matching profile to a file based on its
archive-relative path. This lets a repository preserve more detail in selected
fixture or public-example directories while keeping stricter defaults elsewhere.

Supported profiles are `support`, `public-issue`, `llm-prompt`, `internal`, and
`strict`.
