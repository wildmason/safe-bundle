Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..')
Set-Location $repoRoot

$smokeDir = Join-Path $repoRoot 'target/ci-smoke'
$bundlePath = Join-Path $smokeDir 'support.safe-bundle.zip'
$structuredBundlePath = Join-Path $smokeDir 'structured.safe-bundle.zip'
$providersBundlePath = Join-Path $smokeDir 'providers.safe-bundle.zip'
$receiptPath = Join-Path $smokeDir 'private-redaction-receipt.json'
$extractDir = Join-Path $smokeDir 'unzipped'
$stdinOut = Join-Path $smokeDir 'stdin-redacted.txt'
$scrubOut = Join-Path $smokeDir 'redacted-files'
$scrubEvents = Join-Path $smokeDir 'scrub-redactions.jsonl'
$dryRunEvents = Join-Path $smokeDir 'dry-run-redactions.jsonl'
$checkSarif = Join-Path $smokeDir 'safe-bundle.sarif'
$cleanDir = Join-Path $smokeDir 'clean-input'
$initConfigDir = Join-Path $smokeDir 'init-config'
$initConfigPath = Join-Path $initConfigDir '.safe-bundle.toml'
$policyDir = Join-Path $smokeDir 'policy-input'
$policyConfig = Join-Path $smokeDir '.safe-bundle.toml'
$policyOut = Join-Path $smokeDir 'policy-redacted'

if (Test-Path -LiteralPath $smokeDir) {
    Remove-Item -LiteralPath $smokeDir -Recurse -Force
}
New-Item -ItemType Directory -Path $smokeDir | Out-Null

Write-Host '::group::rules list'
$rules = cargo run --quiet -- rules list --format text
$rules | Write-Host
$rulesText = $rules -join "`n"
if ($rulesText -notmatch 'private-key-pem' -or $rulesText -notmatch 'github-token') {
    throw 'rules list did not include expected detectors'
}
Write-Host '::endgroup::'

Write-Host '::group::release helper script syntax'
foreach ($scriptName in @('install.ps1', 'verify-release.ps1')) {
    $scriptPath = Join-Path $repoRoot "scripts/$scriptName"
    $null = [scriptblock]::Create((Get-Content -Raw -LiteralPath $scriptPath))
}
Write-Host '::endgroup::'

Write-Host '::group::config init'
cargo run --quiet -- config init --path $initConfigPath | Out-Null
$initConfigText = Get-Content -Raw -LiteralPath $initConfigPath
if ($initConfigText -notmatch 'version = 1' -or $initConfigText -notmatch '\[allowlist\]') {
    throw 'config init did not write the expected starter config'
}
$previousErrorActionPreference = $ErrorActionPreference
$ErrorActionPreference = 'Continue'
$configInitExitCode = $null
try {
    cargo run --quiet -- config init --path $initConfigPath 2>&1 | Out-Null
    $configInitExitCode = $LASTEXITCODE
}
finally {
    $ErrorActionPreference = $previousErrorActionPreference
}
if ($configInitExitCode -eq 0) {
    throw 'config init overwrote an existing config without --force'
}
cargo run --quiet -- config init --path $initConfigPath --force | Out-Null
Write-Host '::endgroup::'

Write-Host '::group::completion generation'
$completion = cargo run --quiet -- completions powershell
$completionText = $completion -join "`n"
if ($completionText -notmatch 'safe-bundle' -or $completionText -notmatch 'scrub') {
    throw 'completion generation did not include expected command names'
}
Write-Host '::endgroup::'

Write-Host '::group::scrub files'
cargo run --quiet -- scrub fixtures/synthetic --profile public-issue --out $scrubOut --events $scrubEvents --summary text
$scrubEventsText = Get-Content -Raw -LiteralPath $scrubEvents
if ($scrubEventsText -notmatch '"source_file":"synthetic/app\.env"' -or $scrubEventsText -notmatch '"detector_id":"github-token"') {
    throw 'scrub --events did not emit expected public redaction metadata'
}
cargo run --quiet -- scrub fixtures/synthetic --profile public-issue --dry-run --events $dryRunEvents --summary json | Out-Null
$dryRunEventsText = Get-Content -Raw -LiteralPath $dryRunEvents
if ($dryRunEventsText -notmatch '"source_file":"synthetic/app\.env"' -or $dryRunEventsText -notmatch '"placeholder":"\[REDACTED:') {
    throw 'scrub --dry-run --events did not emit expected public redaction metadata'
}
$previousErrorActionPreference = $ErrorActionPreference
$ErrorActionPreference = 'Continue'
$checkExitCode = $null
try {
    cargo run --quiet -- scrub fixtures/synthetic --profile public-issue --check --sarif $checkSarif --summary json 2>&1 | Out-Null
    $checkExitCode = $LASTEXITCODE
}
finally {
    $ErrorActionPreference = $previousErrorActionPreference
}
if ($checkExitCode -eq 0) {
    throw 'scrub --check succeeded despite fixture redactions'
}
$checkSarifText = Get-Content -Raw -LiteralPath $checkSarif
if ($checkSarifText -match 'ghp_abcdefghijklmnopqrstuvwxyz') {
    throw 'scrub --sarif leaked the GitHub token fixture'
}
$checkSarifJson = $checkSarifText | ConvertFrom-Json
if ($checkSarifJson.version -ne '2.1.0' -or $checkSarifJson.runs[0].results.Count -lt 1) {
    throw 'scrub --sarif did not emit expected SARIF results'
}
New-Item -ItemType Directory -Path $cleanDir | Out-Null
@'
LOG_LEVEL=info
FEATURE_REQUIRED=false
'@ | Set-Content -NoNewline -LiteralPath (Join-Path $cleanDir 'clean.env')
cargo run --quiet -- scrub $cleanDir --profile public-issue --check --exclude '**/.git/**' --summary json | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw 'scrub --check failed on a clean fixture'
}
Write-Host '::endgroup::'

Write-Host '::group::scrub stdin'
'API_KEY=ghp_abcdefghijklmnopqrstuvwxyz' | cargo run --quiet -- scrub --stdin --profile public-issue > $stdinOut
$stdinRedacted = Get-Content -Raw -LiteralPath $stdinOut
if ($stdinRedacted -match 'ghp_abcdefghijklmnopqrstuvwxyz') {
    throw 'stdin scrub leaked the GitHub token fixture'
}
if ($stdinRedacted -notmatch '\[REDACTED:SECRET\.CLOUD_CREDENTIAL:1\]') {
    throw 'stdin scrub did not emit the expected placeholder'
}
Write-Host '::endgroup::'

Write-Host '::group::repository policy config'
New-Item -ItemType Directory -Path (Join-Path $policyDir 'public') | Out-Null
New-Item -ItemType Directory -Path $policyOut | Out-Null
@'
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
pattern = "policy-input/public/**"
profile = "internal"
'@ | Set-Content -NoNewline -LiteralPath $policyConfig
@'
CUSTOM_TOKEN=ticket_redact_this_value
ALLOW_TOKEN=ticket_keep_this_value
CONTACT=policy-contact@example.com
'@ | Set-Content -NoNewline -LiteralPath (Join-Path $policyDir 'public/example.env')

$policyRules = cargo run --quiet -- rules list --config $policyConfig --format text
$policyRulesText = $policyRules -join "`n"
if ($policyRulesText -notmatch 'ticket-token') {
    throw 'rules list --config did not include the custom detector'
}
cargo run --quiet -- scrub $policyDir --profile public-issue --config $policyConfig --exclude '**/.git/**' --out $policyOut --summary text | Out-Null
$policyRedacted = Get-Content -Raw -LiteralPath (Join-Path $policyOut 'policy-input/public/example.env')
if ($policyRedacted -match 'ticket_redact_this_value') {
    throw 'custom detector failed to redact the ticket token'
}
if ($policyRedacted -notmatch 'ticket_keep_this_value') {
    throw 'allowlist literal was redacted unexpectedly'
}
if ($policyRedacted -notmatch 'policy-contact@example.com') {
    throw 'path profile override did not preserve contact email under internal profile'
}
Write-Host '::endgroup::'

Write-Host '::group::bundle and inspect'
cargo run --quiet -- bundle fixtures/synthetic --profile public-issue --out $bundlePath --receipt $receiptPath
$inspect = cargo run --quiet -- inspect $bundlePath --summary text
$inspect | Write-Host
$inspectText = $inspect -join "`n"
if ($inspectText -notmatch 'Files: 3' -or $inspectText -notmatch 'Redactions: 10') {
    throw 'inspect output did not report the expected fixture counts'
}
$verifyInspect = cargo run --quiet -- inspect $bundlePath --verify --summary text
$verifyInspectText = $verifyInspect -join "`n"
if ($verifyInspectText -notmatch 'Verified files: 3' -or $verifyInspectText -notmatch 'Verified redactions: 10') {
    throw 'inspect --verify did not report the expected verified counts'
}
Write-Host '::endgroup::'

Write-Host '::group::structured bundle'
cargo run --quiet -- bundle fixtures/structured --profile public-issue --out $structuredBundlePath
$structuredInspect = cargo run --quiet -- inspect $structuredBundlePath --summary text
$structuredInspect | Write-Host
$structuredInspectText = $structuredInspect -join "`n"
if ($structuredInspectText -notmatch 'Files: 4' -or $structuredInspectText -notmatch 'Redactions: 13') {
    throw 'structured fixture inspect output did not report the expected counts'
}
Write-Host '::endgroup::'

Write-Host '::group::provider token bundle'
cargo run --quiet -- bundle fixtures/providers --profile public-issue --out $providersBundlePath
$providersInspect = cargo run --quiet -- inspect $providersBundlePath --summary text
$providersInspect | Write-Host
$providersInspectText = $providersInspect -join "`n"
if ($providersInspectText -notmatch 'Files: 1' -or $providersInspectText -notmatch 'Redactions: 21') {
    throw 'provider fixture inspect output did not report the expected counts'
}
Write-Host '::endgroup::'

Write-Host '::group::public bundle leak check'
New-Item -ItemType Directory -Path $extractDir | Out-Null
Expand-Archive -LiteralPath $bundlePath -DestinationPath $extractDir -Force

$forbidden = @(
    'ghp_abcdefghijklmnopqrstuvwxyz',
    'supersecret',
    'matt@example.com',
    'api.internal',
    '10.1.2.3',
    'C:\Users\Matt',
    '/home/matt'
)

$publicFiles = Get-ChildItem -LiteralPath $extractDir -Recurse -File
$publicPaths = @($publicFiles | ForEach-Object { $_.FullName }) + @($scrubEvents, $dryRunEvents)
foreach ($needle in $forbidden) {
    $match = Select-String -Path $publicPaths -SimpleMatch -Pattern $needle -Quiet
    if ($match) {
        throw "public bundle leaked fixture value: $needle"
    }
}

$manifest = Get-Content -Raw -LiteralPath (Join-Path $extractDir 'manifest.json') | ConvertFrom-Json
if ($manifest.file_count -ne 3 -or $manifest.redaction_count -ne 10) {
    throw 'manifest counts do not match expected fixture counts'
}

$redactions = Get-Content -Raw -LiteralPath (Join-Path $extractDir 'redactions.jsonl')
if ($redactions -notmatch '"source_file":"synthetic/app\.env"') {
    throw 'redactions.jsonl did not use archive-relative source paths'
}
Write-Host '::endgroup::'

Write-Host '::group::private receipt leak check'
$receipt = Get-Content -Raw -LiteralPath $receiptPath
foreach ($needle in $forbidden) {
    if ($receipt -match [regex]::Escape($needle)) {
        throw "private receipt leaked fixture value: $needle"
    }
}
Write-Host '::endgroup::'

Write-Host 'safe-bundle smoke checks passed.'
