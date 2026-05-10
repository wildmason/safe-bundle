param(
    [string]$Tag,
    [string]$Repository = 'wildmason/safe-bundle',
    [string]$InstallDir,
    [string]$TempDir,
    [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-DefaultTag {
    $latest = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repository/releases/latest"
    return $latest.tag_name
}

function Test-IsWindows {
    if ($env:OS -eq 'Windows_NT') {
        return $true
    }

    $value = Get-Variable -Name IsWindows -ValueOnly -ErrorAction SilentlyContinue
    return $value -eq $true
}

function Test-IsMacOS {
    $value = Get-Variable -Name IsMacOS -ValueOnly -ErrorAction SilentlyContinue
    return $value -eq $true
}

function Test-IsLinux {
    $value = Get-Variable -Name IsLinux -ValueOnly -ErrorAction SilentlyContinue
    return $value -eq $true
}

function Get-PlatformAsset {
    $arch = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()

    if (Test-IsWindows) {
        if ($arch -ne 'X64') {
            throw "unsupported Windows architecture: $arch"
        }
        return @{
            Target = 'x86_64-pc-windows-msvc'
            ArchiveExt = '.zip'
            BinaryName = 'safe-bundle.exe'
        }
    }

    if (Test-IsMacOS) {
        if ($arch -eq 'X64') {
            $target = 'x86_64-apple-darwin'
        }
        elseif ($arch -eq 'Arm64') {
            $target = 'aarch64-apple-darwin'
        }
        else {
            throw "unsupported macOS architecture: $arch"
        }

        return @{
            Target = $target
            ArchiveExt = '.tar.gz'
            BinaryName = 'safe-bundle'
        }
    }

    if (Test-IsLinux) {
        if ($arch -ne 'X64') {
            throw "unsupported Linux architecture: $arch"
        }
        return @{
            Target = 'x86_64-unknown-linux-gnu'
            ArchiveExt = '.tar.gz'
            BinaryName = 'safe-bundle'
        }
    }

    throw 'unsupported operating system'
}

function Invoke-Download {
    param(
        [string]$Uri,
        [string]$OutFile
    )

    Write-Host "Downloading $Uri"
    Invoke-WebRequest -Uri $Uri -OutFile $OutFile
}

if (-not $Tag) {
    $Tag = Get-DefaultTag
}

if (-not $TempDir) {
    $TempDir = Join-Path ([System.IO.Path]::GetTempPath()) 'safe-bundle-install'
}

if (-not $InstallDir) {
    if (Test-IsWindows) {
        $InstallDir = Join-Path $env:LOCALAPPDATA 'safe-bundle/bin'
    }
    else {
        $InstallDir = Join-Path $HOME '.local/bin'
    }
}

$asset = Get-PlatformAsset
$assetName = "safe-bundle-$Tag-$($asset.Target)$($asset.ArchiveExt)"
$baseUrl = "https://github.com/$Repository/releases/download/$Tag"
$workDir = Join-Path $TempDir ([System.Guid]::NewGuid().ToString('n'))
$archivePath = Join-Path $workDir $assetName
$shaPath = "$archivePath.sha256"
$extractDir = Join-Path $workDir 'extract'
$binaryDestination = Join-Path $InstallDir $asset.BinaryName

if ((Test-Path -LiteralPath $binaryDestination) -and -not $Force) {
    throw "$binaryDestination already exists. Pass -Force to overwrite it."
}

New-Item -ItemType Directory -Force -Path $workDir | Out-Null
New-Item -ItemType Directory -Force -Path $extractDir | Out-Null
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null

try {
    Invoke-Download "$baseUrl/$assetName" $archivePath
    Invoke-Download "$baseUrl/$assetName.sha256" $shaPath

    $line = (Get-Content -Raw -LiteralPath $shaPath).Trim()
    if ($line -notmatch '^([A-Fa-f0-9]{64})\s+\*?(.+)$') {
        throw "invalid checksum format in $($assetName).sha256: $line"
    }

    $expectedHash = $Matches[1].ToLowerInvariant()
    $expectedName = $Matches[2].Trim()
    if ($expectedName -ne $assetName) {
        throw "checksum sidecar references $expectedName instead of $assetName"
    }

    $actualHash = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actualHash -ne $expectedHash) {
        throw "checksum mismatch for $assetName`: expected $expectedHash, got $actualHash"
    }

    if ($asset.ArchiveExt -eq '.zip') {
        Expand-Archive -LiteralPath $archivePath -DestinationPath $extractDir -Force
    }
    else {
        tar -xzf $archivePath -C $extractDir
        if ($LASTEXITCODE -ne 0) {
            throw "tar failed with exit code $LASTEXITCODE"
        }
    }

    $binarySource = Join-Path $extractDir $asset.BinaryName
    if (-not (Test-Path -LiteralPath $binarySource)) {
        throw "archive did not contain $($asset.BinaryName)"
    }

    Copy-Item -LiteralPath $binarySource -Destination $binaryDestination -Force

    if (-not (Test-IsWindows)) {
        chmod +x $binaryDestination
        if ($LASTEXITCODE -ne 0) {
            throw "chmod failed with exit code $LASTEXITCODE"
        }
    }

    Write-Host "Installed $assetName to $binaryDestination"
    & $binaryDestination --version

    $pathEntries = ($env:PATH -split [System.IO.Path]::PathSeparator)
    if ($pathEntries -notcontains $InstallDir) {
        Write-Host "Add $InstallDir to PATH to run safe-bundle from any directory."
    }
}
finally {
    if (Test-Path -LiteralPath $workDir) {
        Remove-Item -LiteralPath $workDir -Recurse -Force
    }
}
