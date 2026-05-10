# Automation

`safe-bundle scrub --check` scans inputs, prints the normal summary, writes any
requested metadata outputs, and exits non-zero when redactions are found. It is
equivalent to a dry-run redaction check with `--fail-on findings`, but the
intent is clearer in CI and hooks.

## GitHub Actions

Use the repository action wrapper from a workflow that has already checked out
the target repository:

```yaml
name: safe-bundle

on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read
  security-events: write

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
      - uses: dtolnay/rust-toolchain@stable
      - uses: wildmason/safe-bundle@v1
        with:
          paths: "."
          profile: public-issue
          sarif-output: safe-bundle.sarif
```

For direct CLI use:

```sh
safe-bundle scrub . \
  --profile public-issue \
  --check \
  --sarif safe-bundle.sarif
```

When a lane passes an explicit structured format, fail on invalid source files
too:

```sh
safe-bundle scrub ./fixtures \
  --format json \
  --dry-run \
  --fail-on validation-error \
  --summary json
```

Upload the SARIF file with `github/codeql-action/upload-sarif@v4` when you want
findings in GitHub code scanning.

## pre-commit

For the `pre-commit` framework:

```yaml
repos:
  - repo: local
    hooks:
      - id: safe-bundle-check
        name: safe-bundle scrub check
        entry: safe-bundle scrub --profile public-issue --check
        language: system
        pass_filenames: true
```

## Git Hooks

Example `.git/hooks/pre-commit`:

```sh
#!/bin/sh
set -eu

git diff --cached --name-only --diff-filter=ACMRT |
while IFS= read -r path; do
  [ -n "$path" ] || continue
  safe-bundle scrub "$path" --profile public-issue --check
done
```

Example `.git/hooks/pre-push`:

```sh
#!/bin/sh
set -eu

upstream="$(git rev-parse --abbrev-ref --symbolic-full-name @{u} 2>/dev/null || true)"
if [ -n "$upstream" ]; then
  git diff --name-only --diff-filter=ACMRT "$upstream"...HEAD |
  while IFS= read -r path; do
    [ -n "$path" ] || continue
    safe-bundle scrub "$path" --profile public-issue --check
  done
else
  git diff --name-only --diff-filter=ACMRT HEAD~1...HEAD |
  while IFS= read -r path; do
    [ -n "$path" ] || continue
    safe-bundle scrub "$path" --profile public-issue --check
  done
fi
```
