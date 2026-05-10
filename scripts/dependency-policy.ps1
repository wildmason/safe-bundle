Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..')
Set-Location $repoRoot

$previousErrorActionPreference = $ErrorActionPreference
$ErrorActionPreference = 'Continue'
try {
    $duplicateOutput = cargo tree --locked --duplicates 2>&1
    $duplicateExitCode = $LASTEXITCODE
}
finally {
    $ErrorActionPreference = $previousErrorActionPreference
}
if ($duplicateExitCode -ne 0) {
    throw 'cargo tree --duplicates failed'
}
$duplicateText = ($duplicateOutput | Out-String).Trim()
if ($duplicateText -and $duplicateText -notmatch 'nothing to print') {
    throw "duplicate dependency versions found:`n$duplicateText"
}

$metadata = cargo metadata --locked --format-version 1 | ConvertFrom-Json
$packagesWithoutLicense = @(
    $metadata.packages |
        Where-Object { -not $_.license -and -not $_.license_file } |
        ForEach-Object { $_.name }
)
if ($packagesWithoutLicense.Count -gt 0) {
    throw "packages missing license metadata: $($packagesWithoutLicense -join ', ')"
}

$blockedLicenses = @(
    $metadata.packages |
        Where-Object {
            $_.license -and (
                $_.license -match 'AGPL' -or
                $_.license -match '(?<!L)GPL-'
            )
        } |
        ForEach-Object { "$($_.name): $($_.license)" }
)
if ($blockedLicenses.Count -gt 0) {
    throw "blocked dependency licenses found: $($blockedLicenses -join '; ')"
}

Write-Host "dependency policy checks passed for $($metadata.packages.Count) packages."
