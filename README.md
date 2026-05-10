# safe-bundle

[![CI](https://github.com/wildmason/safe-bundle/actions/workflows/ci.yml/badge.svg)](https://github.com/wildmason/safe-bundle/actions/workflows/ci.yml)

Local-first redaction and safe support bundle CLI.

`safe-bundle` helps developers share useful diagnostics without accidentally
publishing secrets, local identity, private network details, or auth material.
It runs entirely on the local machine: no network calls, no telemetry, no hosted
service.

## What Works Now

- `scrub` redacts stdin or selected files.
- `bundle` writes a `.zip` support bundle containing only redacted files.
- `inspect` validates and summarizes a generated bundle.
- `rules list` prints the built-in detector catalog.
- Valid JSON, JSONL, TOML, YAML, and env inputs are checked after redaction so
  structure-breaking replacements fail instead of producing broken artifacts.
- Stable placeholders preserve debugging shape:
  `[REDACTED:SECRET.API_KEY:1]`.
- Public redaction events never include raw secret values.
- `scrub --events` writes public JSONL finding metadata without building a
  bundle.
- `scrub --check` and `scrub --sarif` support CI, hooks, and GitHub code
  scanning workflows.
- Optional private receipts store hashes and source spans for sender-side
  correlation without copying raw secrets.

Supported MVP detectors include:

- PEM private keys.
- Bearer tokens and JWT-like tokens.
- Secret-like key/value pairs.
- Common cloud credentials: AWS, GitHub, Stripe, Stripe webhooks, npm, OpenAI,
  Anthropic, Slack, Discord, Fly.io, Resend, Lemon Squeezy, Google API keys,
  Azure storage account keys, SendGrid, Datadog, Netlify, Vercel, Postmark,
  Sentry, Supabase service-role keys, and Twilio auth tokens.
- Database and service connection strings.
- URL password segments.
- Windows and Unix home directory usernames.
- Private IPv4 addresses.
- Email addresses and internal URLs in more aggressive profiles.

## Install From Source

Download release assets from the
[GitHub Releases](https://github.com/wildmason/safe-bundle/releases) page and
verify the matching `.sha256` file before using a binary.

From a local checkout:

```sh
cargo install --path .
```

From GitHub:

```sh
cargo install --git https://github.com/wildmason/safe-bundle.git --locked
```

During development:

```sh
cargo run -- --help
```

## Repository Policy

`safe-bundle` can load `.safe-bundle.toml` from the current directory or an
ancestor. Use it for repository-local allowlists, custom detectors, and per-path
profile overrides. Pass `--config <path>` for an explicit file or `--no-config`
to force built-in behavior.

```toml
version = 1

[allowlist]
literals = ["ticket_keep_this_value"]

[[custom_detectors]]
id = "ticket-token"
pattern = "ticket_[A-Za-z0-9_]{12,}"
class = "secret.api_key"
confidence = "high"
reason = "ticket fixture token"

[[path_overrides]]
pattern = "public/**"
profile = "internal"
```

See [configuration](docs/CONFIG.md) for the full schema.

## Scrub Files

```sh
cargo run -- scrub fixtures/synthetic --out target/redacted
```

For stdin:

```sh
echo "API_KEY=ghp_abcdefghijklmnopqrstuvwxyz" | cargo run -- scrub --stdin
```

Write a private receipt:

```sh
cargo run -- scrub fixtures/synthetic \
  --out target/redacted \
  --receipt target/private-redaction-receipt.json
```

Write public finding metadata for CI or review:

```sh
cargo run -- scrub fixtures/synthetic \
  --dry-run \
  --events target/redactions.jsonl \
  --summary json
```

Run a CI-friendly check and write SARIF:

```sh
cargo run -- scrub fixtures/synthetic \
  --profile public-issue \
  --check \
  --sarif target/safe-bundle.sarif
```

## Build a Support Bundle

```sh
cargo run -- bundle fixtures/synthetic \
  --profile public-issue \
  --out target/support.safe-bundle.zip \
  --receipt target/private-redaction-receipt.json
```

Structured format smoke:

```sh
cargo run -- bundle fixtures/structured \
  --profile public-issue \
  --out target/structured.safe-bundle.zip
```

Provider-token smoke:

```sh
cargo run -- bundle fixtures/providers \
  --profile public-issue \
  --out target/providers.safe-bundle.zip
```

Bundle layout:

```text
manifest.json
summary.md
redactions.jsonl
files/
skipped.jsonl
checksums.sha256
README.txt
```

The public bundle does not include original files or raw sensitive values.

## Inspect a Bundle

```sh
cargo run -- inspect target/support.safe-bundle.zip
cargo run -- inspect target/support.safe-bundle.zip --summary json
cargo run -- inspect target/support.safe-bundle.zip --verify
```

## Profiles

- `support`: default. Redacts secrets, auth material, local user identity, and
  private network identity.
- `public-issue`: also redacts medium-confidence contact info and internal
  endpoints.
- `llm-prompt`: same aggressive posture as public issue mode for the MVP.
- `internal`: redacts secrets/auth material but preserves more local detail.
- `strict`: redacts every built-in detector class.

## Limits

This is a developer safety tool, not a legal de-identification guarantee. It
uses deterministic detectors for known high-value classes and preserves
diagnostic structure where possible. Arbitrary free text can still contain
sensitive information that no local detector recognizes.

## Development

```sh
cargo fmt
cargo test
cargo clippy --all-targets -- -D warnings
pwsh ./scripts/ci-smoke.ps1
pwsh ./scripts/dependency-policy.ps1
cargo +1.85.0 check --locked
```

On Windows without PowerShell Core installed, the smoke script also works with:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\ci-smoke.ps1
```

Additional project docs:

- [Threat model](docs/THREAT_MODEL.md)
- [Configuration](docs/CONFIG.md)
- [Bundle format](docs/BUNDLE_FORMAT.md)
- [Automation](docs/AUTOMATION.md)
- [Roadmap to 1.0](docs/ROADMAP.md)
- [Release process](docs/RELEASE.md)
- [Contributing](CONTRIBUTING.md)
- [Security policy](SECURITY.md)
- [Changelog](CHANGELOG.md)

## License

MIT OR Apache-2.0.
