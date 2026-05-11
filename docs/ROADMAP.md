# Roadmap

`safe-bundle` reached its stable local safety contract in `1.0.0`. The roadmap
now tracks shipped milestones and the next practical release lanes.

## Shipped Milestones

### 1.0.0 - Stable Local Safety Contract

Status: shipped on 2026-05-10.

`1.0.0` means users can install `safe-bundle`, configure it in a repository,
run it locally or in CI, trust the public bundle format, and understand the
tool's guarantees and limits.

- Golden detector corpus and structured-output validity coverage.
- Repository policy loading from `.safe-bundle.toml`.
- Documented schema-v1 `.safe-bundle.zip` bundle contract.
- `inspect --verify`, `scrub --check`, SARIF output, and GitHub Action
  automation.
- MSRV, dependency policy, release-asset smoke tests, and GitHub artifact
  attestations.
- User-facing workflow, contribution, support, and release-candidate docs.

### 1.1.0 - Distribution and Policy UX

Status: shipped on 2026-05-11.

`1.1.0` makes the stable CLI easier to install, verify, configure, and package
without changing the public bundle schema.

- GitHub Release installer and release verification scripts.
- Homebrew and Scoop recipe generation backed by release checksum sidecars.
- Published package-manager recipes in Wildmason-owned tap and bucket
  repositories.
- Install, distribution, packaging, and release-process documentation.
- Shell completion generation for Bash, Elvish, Fish, PowerShell, and Zsh.
- `config init`, `config validate`, and `config inspect` repository policy
  helpers.
- Formatted `rules test` output and `--fail-on validation-error` enforcement.
- Expanded provider detector coverage.
- CI package and crates.io publish dry-run gates.

## Next Candidates

### Detector Quality and Corpus Growth

- Add more real-world false-positive fixtures for common framework config.
- Expand provider detector coverage only when matching confidence is testable.
- Keep every detector addition tied to golden fixtures and public-output
  leakage tests.

### Package-Manager Smoke Automation

- Add scheduled or release-time Homebrew and Scoop install smoke coverage when
  runners with those package managers are available.
- Keep formula and manifest updates version-for-version with GitHub Releases.

### Windows Package Channels

- Revisit Winget after the Windows distribution format is final, likely using
  the GitHub Release zip as the upstream portable artifact.
