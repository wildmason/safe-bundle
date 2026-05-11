# Distribution

`safe-bundle` is distributed through crates.io and GitHub Releases. Crates.io
publication remains a manual maintainer step for each release.

Package-manager recipe generation is documented in
[package manager recipes](PACKAGING.md). End-user installation options are
covered in the [install guide](INSTALL.md).

## GitHub Releases

Each release publishes platform archives, a packaged crate archive, SHA-256
sidecars, and GitHub artifact attestations.

Supported binary archives:

- `safe-bundle-v<version>-x86_64-unknown-linux-gnu.tar.gz`
- `safe-bundle-v<version>-x86_64-apple-darwin.tar.gz`
- `safe-bundle-v<version>-aarch64-apple-darwin.tar.gz`
- `safe-bundle-v<version>-x86_64-pc-windows-msvc.zip`

## Install From GitHub Releases

Use the PowerShell installer from a checkout:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\install.ps1 -Tag v1.0.0
```

By default, the installer chooses the archive for the current platform,
downloads the matching `.sha256` sidecar, verifies the archive hash, extracts
the binary, and installs it to:

- Windows: `%LOCALAPPDATA%\safe-bundle\bin`
- macOS/Linux: `$HOME/.local/bin`

Use `-InstallDir <path>` for a different destination and `-Force` to overwrite
an existing binary.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\install.ps1 `
  -Tag v1.0.0 `
  -InstallDir .\target\install-bin `
  -Force
```

## Shell Completions

Generate completion scripts from the installed binary:

```sh
safe-bundle completions bash > safe-bundle.bash
safe-bundle completions zsh > _safe-bundle
safe-bundle completions fish > safe-bundle.fish
safe-bundle completions powershell > safe-bundle.ps1
```

Install the generated file using the conventions for the target shell or
package manager.

## Verify A Release

Maintainers can verify all published release assets with:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\verify-release.ps1 -Tag v1.0.0
```

The verifier downloads every release asset, checks every `.sha256` sidecar, and
then runs `gh attestation verify` for every non-sidecar asset against the tag
ref.

Requirements:

- GitHub CLI installed and authenticated for attestation lookup.
- Network access to GitHub Releases and GitHub artifact attestations.

Use `-SkipAttestations` for checksum-only verification.

To verify already downloaded assets without GitHub CLI or network access, pass
an asset directory and skip attestations:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\verify-release.ps1 `
  -AssetDir .\target\release-check\v1.0.0 `
  -SkipAttestations
```

## Crates.io

The `1.0.0` crate was published from the `v1.0.0` tag. Future release crates
should also be published from their release tag, not from a later post-release
`main` checkout:

```powershell
git checkout v1.0.0
cargo publish --dry-run --locked
cargo publish --locked
```

Publishing requires a crates.io account, an API token available through
`cargo login <token>` or `CARGO_REGISTRY_TOKEN`, owner permission for the
crate, and a version number that has not already been accepted by crates.io.

Once crates.io accepts a version, that version is immutable. A bad release can
be yanked, but the same version number cannot be reused with different contents.
