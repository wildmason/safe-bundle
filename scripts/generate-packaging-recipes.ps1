param(
    [string]$Tag,
    [string]$Repository = 'wildmason/safe-bundle',
    [string]$OutDir,
    [string]$SidecarDir
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
        throw 'GitHub CLI (`gh`) is required unless -SidecarDir is provided.'
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

function Read-SidecarHash {
    param(
        [string]$SidecarDir,
        [string]$AssetName
    )

    $sidecarPath = Join-Path $SidecarDir "$AssetName.sha256"
    if (-not (Test-Path -LiteralPath $sidecarPath)) {
        throw "missing checksum sidecar for $AssetName"
    }

    $line = (Get-Content -Raw -LiteralPath $sidecarPath).Trim()
    if ($line -notmatch '^([A-Fa-f0-9]{64})\s+\*?(.+)$') {
        throw "invalid checksum format in $($AssetName).sha256: $line"
    }

    $expectedName = $Matches[2].Trim()
    if ($expectedName -ne $AssetName) {
        throw "checksum sidecar references $expectedName instead of $AssetName"
    }

    return $Matches[1].ToLowerInvariant()
}

if (-not $Tag) {
    $Tag = Get-DefaultTag
}

$version = $Tag -replace '^v', ''
$repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..')
if (-not $OutDir) {
    $OutDir = Join-Path $repoRoot "target/packaging/$Tag"
}

$downloadSidecarDir = Join-Path $OutDir 'sidecars'
$homebrewDir = Join-Path $OutDir 'homebrew'
$scoopDir = Join-Path $OutDir 'scoop'
New-Item -ItemType Directory -Force -Path $downloadSidecarDir, $homebrewDir, $scoopDir | Out-Null

if ($SidecarDir) {
    $readSidecarDir = (Resolve-Path -LiteralPath $SidecarDir).ProviderPath
}
else {
    Assert-GitHubCli
    Invoke-Checked gh @(
        'release',
        'download',
        $Tag,
        '--repo',
        $Repository,
        '--dir',
        $downloadSidecarDir,
        '--clobber',
        '--pattern',
        '*.sha256'
    )
    $readSidecarDir = $downloadSidecarDir
}

$assetBase = "https://github.com/$Repository/releases/download/$Tag"
$linuxAsset = "safe-bundle-$Tag-x86_64-unknown-linux-gnu.tar.gz"
$macIntelAsset = "safe-bundle-$Tag-x86_64-apple-darwin.tar.gz"
$macArmAsset = "safe-bundle-$Tag-aarch64-apple-darwin.tar.gz"
$windowsAsset = "safe-bundle-$Tag-x86_64-pc-windows-msvc.zip"

$linuxHash = Read-SidecarHash $readSidecarDir $linuxAsset
$macIntelHash = Read-SidecarHash $readSidecarDir $macIntelAsset
$macArmHash = Read-SidecarHash $readSidecarDir $macArmAsset
$windowsHash = Read-SidecarHash $readSidecarDir $windowsAsset

$homebrewFormula = @"
class SafeBundle < Formula
  desc "Local-first redaction and safe support bundle CLI"
  homepage "https://github.com/$Repository"
  version "$version"
  license any_of: ["MIT", "Apache-2.0"]

  on_macos do
    if Hardware::CPU.arm?
      url "$assetBase/$macArmAsset"
      sha256 "$macArmHash"
    else
      url "$assetBase/$macIntelAsset"
      sha256 "$macIntelHash"
    end
  end

  on_linux do
    if Hardware::CPU.intel?
      url "$assetBase/$linuxAsset"
      sha256 "$linuxHash"
    end
  end

  def install
    bin.install "safe-bundle"
  end

  test do
    assert_match "safe-bundle #{version}", shell_output("#{bin}/safe-bundle --version")
  end
end
"@

$homebrewPath = Join-Path $homebrewDir 'safe-bundle.rb'
Set-Content -LiteralPath $homebrewPath -Value $homebrewFormula -NoNewline

$scoopManifest = [ordered]@{
    version = $version
    description = 'Local-first redaction and safe support bundle CLI'
    homepage = "https://github.com/$Repository"
    license = 'MIT OR Apache-2.0'
    architecture = [ordered]@{
        '64bit' = [ordered]@{
            url = "$assetBase/$windowsAsset"
            hash = $windowsHash
        }
    }
    bin = 'safe-bundle.exe'
    checkver = [ordered]@{
        github = $Repository
    }
    autoupdate = [ordered]@{
        architecture = [ordered]@{
            '64bit' = [ordered]@{
                url = "https://github.com/$Repository/releases/download/v`$version/safe-bundle-v`$version-x86_64-pc-windows-msvc.zip"
            }
        }
    }
}

$scoopPath = Join-Path $scoopDir 'safe-bundle.json'
$scoopManifest | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $scoopPath

Write-Host "Generated Homebrew formula: $homebrewPath"
Write-Host "Generated Scoop manifest: $scoopPath"
