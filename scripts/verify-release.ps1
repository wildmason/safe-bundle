param(
    [string]$Tag,
    [string]$Repository = 'wildmason/safe-bundle',
    [string]$Destination,
    [string]$AssetDir,
    [switch]$SkipAttestations
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Invoke-Checked {
    param(
        [string]$FilePath,
        [string[]]$ArgumentList
    )

    & $FilePath @ArgumentList
    if ($LASTEXITCODE -ne 0) {
        throw "$FilePath failed with exit code $LASTEXITCODE"
    }
}

function Assert-GitHubCli {
    if (-not (Get-Command gh -ErrorAction SilentlyContinue)) {
        throw 'GitHub CLI (`gh`) is required to download release assets or verify attestations.'
    }
}

function Get-DefaultTag {
    Assert-GitHubCli

    $tag = gh release view --repo $Repository --json tagName --jq '.tagName'
    if ($LASTEXITCODE -ne 0) {
        throw "could not determine latest release tag for $Repository"
    }

    return $tag.Trim()
}

if ($AssetDir -and $Destination) {
    throw 'Pass either -AssetDir or -Destination, not both.'
}

if (-not $Tag) {
    if ($AssetDir) {
        $Tag = 'local-assets'
    }
    else {
        $Tag = Get-DefaultTag
    }
}

if ($AssetDir) {
    $Destination = (Resolve-Path -LiteralPath $AssetDir).ProviderPath
}
else {
    Assert-GitHubCli

    if (-not $Destination) {
        $repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..')
        $Destination = Join-Path $repoRoot "target/release-check/$Tag"
    }

    New-Item -ItemType Directory -Force -Path $Destination | Out-Null

    Write-Host "Downloading release assets for $Repository $Tag to $Destination"
    Invoke-Checked gh @('release', 'download', $Tag, '--repo', $Repository, '--dir', $Destination, '--clobber')
}

$shaFiles = @(Get-ChildItem -LiteralPath $Destination -File -Filter '*.sha256')
if ($shaFiles.Count -eq 0) {
    throw "no .sha256 sidecar files were downloaded for $Tag"
}

foreach ($shaFile in $shaFiles) {
    $line = (Get-Content -Raw -LiteralPath $shaFile.FullName).Trim()
    if ($line -notmatch '^([A-Fa-f0-9]{64})\s+\*?(.+)$') {
        throw "invalid checksum format in $($shaFile.Name): $line"
    }

    $expectedHash = $Matches[1].ToLowerInvariant()
    $assetName = $Matches[2].Trim()
    $assetPath = Join-Path $shaFile.DirectoryName $assetName
    if (-not (Test-Path -LiteralPath $assetPath)) {
        throw "checksum sidecar $($shaFile.Name) references missing asset $assetName"
    }

    $actualHash = (Get-FileHash -LiteralPath $assetPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actualHash -ne $expectedHash) {
        throw "checksum mismatch for $assetName`: expected $expectedHash, got $actualHash"
    }

    Write-Host "Verified checksum: $assetName"
}

if (-not $SkipAttestations) {
    Assert-GitHubCli
    if ($Tag -eq 'local-assets') {
        throw 'Tag is required for attestation verification when -AssetDir is used.'
    }

    $assets = @(
        Get-ChildItem -LiteralPath $Destination -File |
            Where-Object { $_.Name -notlike '*.sha256' }
    )

    foreach ($asset in $assets) {
        Invoke-Checked gh @(
            'attestation',
            'verify',
            $asset.FullName,
            '--repo',
            $Repository,
            '--source-ref',
            "refs/tags/$Tag"
        )
        Write-Host "Verified attestation: $($asset.Name)"
    }
}

Write-Host "Release verification passed for $Repository $Tag."
