# Package Manager Recipes

`safe-bundle` is distributed through Wildmason-owned package-manager
repositories that consume GitHub Release archives. The source repository keeps
recipe generation scripted, but does not commit generated package-manager
files.

Live repositories:

- Homebrew tap: `https://github.com/wildmason/homebrew-tap`
- Scoop bucket: `https://github.com/wildmason/scoop-bucket`

## Generate Recipes

Run from a checkout after the GitHub Release workflow has published assets and
SHA-256 sidecars:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\generate-packaging-recipes.ps1 -Tag v1.0.0
```

The script downloads checksum sidecars for the release tag and writes draft
recipes under `target/packaging/<tag>/`:

```text
homebrew/safe-bundle.rb
scoop/safe-bundle.json
```

These files are generated release artifacts. Publish them to the relevant tap or
bucket repository after reviewing the rendered URLs and hashes.

For offline validation or CI smoke coverage, pass a directory that already
contains the release `.sha256` sidecars:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\generate-packaging-recipes.ps1 `
  -Tag v1.0.0 `
  -SidecarDir .\target\release-sidecars `
  -OutDir .\target\packaging\v1.0.0
```

## Homebrew

The generated formula is suitable for `wildmason/homebrew-tap`. Review the
formula, then copy it to the tap as `Formula/safe-bundle.rb`.

The formula installs from the GitHub Release archives:

- macOS Apple Silicon: `aarch64-apple-darwin`
- macOS Intel: `x86_64-apple-darwin`
- Linux Intel: `x86_64-unknown-linux-gnu`

After pushing the tap update, test a clean install:

```sh
brew install wildmason/tap/safe-bundle
safe-bundle --version
```

## Scoop

The generated Scoop manifest is suitable for `wildmason/scoop-bucket`. Review
the manifest, then copy it to the bucket as `bucket/safe-bundle.json`.

The manifest installs the Windows archive:

- Windows x64: `x86_64-pc-windows-msvc`

After pushing the bucket update, test a clean install:

```powershell
scoop bucket add wildmason https://github.com/wildmason/scoop-bucket
scoop install safe-bundle
safe-bundle --version
```

## Winget

Winget packaging should wait until there is a stable maintainer decision about
whether `safe-bundle` will ship as a portable executable, zip-based portable
package, or installer. Use the GitHub Release Windows archive as the upstream
artifact and keep the manifest version aligned with the release tag.

## Release Discipline

- Generate recipes only after the GitHub Release is published and verified.
- Use the `.sha256` sidecars from the release, not locally recomputed hashes.
- Do not publish package-manager recipes for a failed or draft release.
- Keep package-manager updates version-for-version with GitHub Releases.
