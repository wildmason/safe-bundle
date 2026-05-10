# safe-bundle

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
- Stable placeholders preserve debugging shape:
  `[REDACTED:SECRET.API_KEY:1]`.
- Public redaction events never include raw secret values.
- Optional private receipts store hashes and source spans for sender-side
  correlation without copying raw secrets.

Supported MVP detectors include:

- PEM private keys.
- Bearer tokens and JWT-like tokens.
- Secret-like key/value pairs.
- Common cloud credentials: AWS, GitHub, Stripe, npm.
- Database and service connection strings.
- URL password segments.
- Windows and Unix home directory usernames.
- Private IPv4 addresses.
- Email addresses and internal URLs in more aggressive profiles.

## Install From Source

```sh
cargo install --path .
```

During development:

```sh
cargo run -- --help
```

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

## Build a Support Bundle

```sh
cargo run -- bundle fixtures/synthetic \
  --profile public-issue \
  --out target/support.safe-bundle.zip \
  --receipt target/private-redaction-receipt.json
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
```

## License

MIT OR Apache-2.0.
