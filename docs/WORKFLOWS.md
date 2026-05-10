# Workflows

These workflows use synthetic examples. Do not paste live credentials, customer
logs, private support bundles, production screenshots, or private repo contents
into public issues or examples.

## Before Opening a Public Issue

Use this when you need to attach diagnostics to a public GitHub issue.

1. Put the files you plan to share in a review directory.
2. Run:

   ```sh
   safe-bundle bundle ./issue-artifacts \
     --profile public-issue \
     --out ./public-issue.safe-bundle.zip \
     --receipt ./private-redaction-receipt.json
   ```

3. Verify the bundle:

   ```sh
   safe-bundle inspect ./public-issue.safe-bundle.zip --verify
   ```

4. Extract or open the bundle locally and review:

   - `summary.md`
   - `redactions.jsonl`
   - every file under `files/`
   - `skipped.jsonl`

5. Attach only the `.safe-bundle.zip` to the public issue. Keep the private
   receipt local unless a trusted support contact explicitly asks for it through
   a private channel.

If the bundle still contains something you would not post by hand, do not share
it. Add a custom detector, use `strict`, or remove that file from the artifact
set.

## Public GitHub Issue Example

```sh
safe-bundle bundle ./repro \
  --profile public-issue \
  --out ./repro.safe-bundle.zip

safe-bundle inspect ./repro.safe-bundle.zip --verify
```

Issue body:

```markdown
I attached `repro.safe-bundle.zip`, generated with:

- Tool: safe-bundle
- Profile: public-issue
- Verified: yes, with `safe-bundle inspect --verify`

The bundle contains redacted logs and request metadata only. I reviewed the
`files/` entries before attaching.
```

## Support Handoff

Use this when sending diagnostics to a private vendor or internal support team.

```sh
safe-bundle bundle ./support-artifacts \
  --profile support \
  --out ./support.safe-bundle.zip \
  --receipt ./private-redaction-receipt.json
```

Send the bundle first. Keep the receipt local. The receipt lets you correlate
placeholders with local source spans and raw-value hashes without copying raw
values into the support channel.

For a stricter vendor handoff, use:

```sh
safe-bundle bundle ./support-artifacts \
  --profile public-issue \
  --out ./support.safe-bundle.zip \
  --receipt ./private-redaction-receipt.json
```

## LLM Prompt Cleanup

Use this before pasting logs, traces, HTTP transcripts, diffs, or config snippets
into an LLM chat.

```sh
safe-bundle scrub ./prompt-material \
  --profile llm-prompt \
  --out ./prompt-redacted
```

For clipboard-sized snippets:

```sh
safe-bundle scrub --stdin --profile llm-prompt
```

Review the redacted output before pasting it. `safe-bundle` removes supported
high-value patterns, but it cannot understand every business-sensitive sentence
or proprietary source-code detail.

## Internal Incident Triage

Use this when you suspect a log, archive, crash report, or copied prompt contains
credentials or private identity data.

```sh
safe-bundle scrub ./incident-artifacts \
  --profile strict \
  --dry-run \
  --events ./incident-redactions.jsonl \
  --summary markdown
```

Then create a reviewed bundle:

```sh
safe-bundle bundle ./incident-artifacts \
  --profile strict \
  --out ./incident.safe-bundle.zip \
  --receipt ./incident-private-receipt.json

safe-bundle inspect ./incident.safe-bundle.zip --verify
```

Treat `incident-private-receipt.json` as internal-only. It is useful for local
correlation and audit work, not for broad distribution.

## CI Preflight

Use `--check` to fail a job when supported redaction patterns are present:

```sh
safe-bundle scrub . \
  --profile public-issue \
  --check \
  --sarif safe-bundle.sarif
```

This is a prevention gate, not a replacement for reviewing artifacts before
publication.
