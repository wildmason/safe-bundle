# Release Process

`safe-bundle` releases are tag driven.

## Preflight

1. Confirm the working tree is clean.
2. Update `CHANGELOG.md`.
3. Run the local gate:

   ```sh
   cargo fmt -- --check
   cargo test --locked
   cargo clippy --all-targets --locked -- -D warnings
   powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\ci-smoke.ps1
   powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\dependency-policy.ps1
   cargo +1.85.0 check --locked
   cargo package --locked
   ```

4. Confirm GitHub Actions is green on `main`.
5. Confirm repository rules allow maintainers or release automation to create
   `refs/tags/v*` tags. If tag creation is restricted, the tag push will fail
   before the release workflow can run.

## Tag

Use an annotated version tag:

```sh
git tag -a v1.0.0 -m "safe-bundle v1.0.0"
git push origin v1.0.0
```

The `Release` workflow verifies the tag, creates a draft GitHub Release, builds
cross-platform binaries, uploads checksums, and publishes the draft when all
jobs pass.

## Artifacts

The release workflow uploads:

- `safe-bundle-<version>-x86_64-unknown-linux-gnu.tar.gz`
- `safe-bundle-<version>-x86_64-apple-darwin.tar.gz`
- `safe-bundle-<version>-aarch64-apple-darwin.tar.gz`
- `safe-bundle-<version>-x86_64-pc-windows-msvc.zip`
- `.sha256` sidecar files for every archive.
- The packaged crate archive from `cargo package`.

Each binary archive is extracted and smoke-tested in the release workflow before
it is uploaded.

## Integrity and Provenance

Every uploaded archive must have a SHA-256 sidecar file. The release workflow
extracts and smoke-tests each packaged binary before upload.

The release workflow also generates GitHub artifact attestations for the crate
archive and binary archives. Verify them with:

```sh
gh attestation verify <artifact> -R wildmason/safe-bundle
```

Detached GPG or cosign signatures are not required unless downstream packaging
or distribution channels need them.

## Crates.io

Crates.io publication is intentionally manual until the project has a dedicated
publish token and final ownership metadata:

```sh
cargo publish --dry-run --locked
cargo publish --locked
```

Do not publish if the GitHub Release workflow failed.
