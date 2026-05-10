Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..')
Set-Location $repoRoot

$smokeDir = Join-Path $repoRoot 'target/ci-smoke'
$bundlePath = Join-Path $smokeDir 'support.safe-bundle.zip'
$receiptPath = Join-Path $smokeDir 'private-redaction-receipt.json'
$extractDir = Join-Path $smokeDir 'unzipped'
$stdinOut = Join-Path $smokeDir 'stdin-redacted.txt'
$scrubOut = Join-Path $smokeDir 'redacted-files'

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

Write-Host '::group::scrub files'
cargo run --quiet -- scrub fixtures/synthetic --profile public-issue --out $scrubOut --summary text
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

Write-Host '::group::bundle and inspect'
cargo run --quiet -- bundle fixtures/synthetic --profile public-issue --out $bundlePath --receipt $receiptPath
$inspect = cargo run --quiet -- inspect $bundlePath --summary text
$inspect | Write-Host
$inspectText = $inspect -join "`n"
if ($inspectText -notmatch 'Files: 3' -or $inspectText -notmatch 'Redactions: 10') {
    throw 'inspect output did not report the expected fixture counts'
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
$publicPaths = $publicFiles | ForEach-Object { $_.FullName }
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
