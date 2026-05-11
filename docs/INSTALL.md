# Install safe-bundle

`safe-bundle` is distributed through crates.io and GitHub Releases. Source
installs are also supported for developers and early adopters. Package-manager
publication is a maintainer-controlled follow-up step.

## GitHub Release Installer

From a repository checkout, install the matching release binary for the current
platform:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\install.ps1 -Tag v1.0.0
```

The installer detects the current operating system and CPU, downloads the
matching archive and `.sha256` sidecar, verifies the archive hash, extracts the
binary, and installs it to:

- Windows: `%LOCALAPPDATA%\safe-bundle\bin`
- macOS/Linux: `$HOME/.local/bin`

Use `-InstallDir` to choose a different directory:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\install.ps1 `
  -Tag v1.0.0 `
  -InstallDir .\target\install-bin `
  -Force
```

Add the install directory to `PATH` if the shell cannot find `safe-bundle`
after installation.

## Manual Release Install

Download the archive for the target platform from the GitHub Release:

- Linux x64: `safe-bundle-v<version>-x86_64-unknown-linux-gnu.tar.gz`
- macOS Intel: `safe-bundle-v<version>-x86_64-apple-darwin.tar.gz`
- macOS Apple Silicon: `safe-bundle-v<version>-aarch64-apple-darwin.tar.gz`
- Windows x64: `safe-bundle-v<version>-x86_64-pc-windows-msvc.zip`

Download the matching `.sha256` sidecar before extracting the binary. On
Windows, verify the archive hash with:

```powershell
Get-FileHash .\safe-bundle-v1.0.0-x86_64-pc-windows-msvc.zip -Algorithm SHA256
Get-Content .\safe-bundle-v1.0.0-x86_64-pc-windows-msvc.zip.sha256
```

On macOS or Linux, verify with:

```sh
sha256sum -c safe-bundle-v1.0.0-x86_64-unknown-linux-gnu.tar.gz.sha256
```

Then extract the archive, move `safe-bundle` or `safe-bundle.exe` into a
directory on `PATH`, and confirm the install:

```sh
safe-bundle --version
safe-bundle --help
```

## Cargo Installs

From crates.io:

```sh
cargo install safe-bundle --locked
```

From a local checkout:

```sh
cargo install --path .
```

From GitHub:

```sh
cargo install --git https://github.com/wildmason/safe-bundle.git --locked
```

## Shell Completions

Generate completion scripts with the installed binary:

```sh
safe-bundle completions bash > safe-bundle.bash
safe-bundle completions zsh > _safe-bundle
safe-bundle completions fish > safe-bundle.fish
safe-bundle completions powershell > safe-bundle.ps1
```

Install the generated file using the conventions for the target shell or the
package manager that installed `safe-bundle`.

## Repository Policy Setup

For a repository-local policy file:

```sh
safe-bundle config init
safe-bundle config validate --require
safe-bundle config inspect
```

Commit `.safe-bundle.toml` when the allowlist, custom detectors, or path
profile overrides should apply to everyone working in the repository.

## Package Managers

Homebrew and Scoop recipes are generated from verified GitHub Release assets,
but the generated recipes live in downstream tap or bucket repositories. See
[package manager recipes](PACKAGING.md) for the maintainer workflow.

Winget packaging is deferred until the Windows distribution format is finalized.
