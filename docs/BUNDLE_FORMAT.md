# Bundle Format

`safe-bundle bundle` writes a ZIP archive with a stable top-level layout.

```text
manifest.json
summary.md
redactions.jsonl
skipped.jsonl
checksums.sha256
README.txt
files/
```

The current schema version is `1`.

## Compatibility

`safe-bundle` treats schema `1` as the supported bundle format for the `1.x`
CLI line. Patch and minor releases may add optional manifest fields or public
redaction fields, but they must keep existing schema `1` fields and top-level
entries readable by newer `1.x` releases.

Any incompatible bundle layout change must use a new `schema_version`. Current
releases reject unknown schema versions during `inspect --verify` instead of
silently accepting a bundle they cannot validate.

## `manifest.json`

The manifest is the machine-readable bundle header.

Important fields:

- `schema_version`: currently `"1"`.
- `tool_name` / `tool_version`: producing tool identity.
- `created_at`: UTC timestamp.
- `profile`: default profile used for the bundle.
- `policy`: policy source summary.
- `input_roots`: redacted input roots.
- `file_count`, `redacted_file_count`, `skipped_file_count`, and
  `redaction_count`: summary counts.
- `classes`: redaction counts by class.
- `redacted_output_hashes`: SHA-256 for each `files/...` entry.
- `bundle_hash`: logical hash over file hashes and public redaction metadata.

## `redactions.jsonl`

One public redaction event per line. Events include detector id, class,
confidence, source spans, redacted spans, placeholders, length bucket, and
public context. They do not include raw sensitive values.

## `skipped.jsonl`

One skipped-file record per line. Paths are redacted through the selected
profile before being written.

## `checksums.sha256`

Two-space-separated SHA-256 records for every redacted output file:

```text
<sha256>  files/<archive-relative-path>
```

## `files/`

Redacted file content only. Original files are never stored in the public
bundle.

## Verification

Use:

```sh
safe-bundle inspect support.safe-bundle.zip --verify
```

Verification checks required entries, schema version, `checksums.sha256`,
redacted file hashes, `redactions.jsonl` parseability, redaction count, and the
manifest logical `bundle_hash`.
