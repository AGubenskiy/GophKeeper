param(
    [string]$Version = "",
    [string]$DistDir = "dist",
    [string]$OutDir = "release",
    [switch]$Clean
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Resolve-RepoPath {
    param([string]$Path)

    if ([System.IO.Path]::IsPathRooted($Path)) {
        return $Path
    }
    return Join-Path $repoRoot $Path
}

function Assert-InRepository {
    param([string]$Path)

    $resolved = (Resolve-Path -LiteralPath $Path).Path
    $prefix = $repoRoot
    if (-not $prefix.EndsWith([System.IO.Path]::DirectorySeparatorChar)) {
        $prefix += [System.IO.Path]::DirectorySeparatorChar
    }
    if ($resolved -eq $repoRoot -or -not $resolved.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "refusing to operate outside repository: $resolved"
    }
    return $resolved
}

function Copy-IfExists {
    param(
        [string]$Source,
        [string]$Destination
    )

    if (Test-Path -LiteralPath $Source) {
        Copy-Item -LiteralPath $Source -Destination $Destination -Recurse -Force
    }
}

$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = (Resolve-Path -LiteralPath (Join-Path $scriptRoot "..")).Path
$distPath = Resolve-RepoPath -Path $DistDir
$outPath = Resolve-RepoPath -Path $OutDir

if ([string]::IsNullOrWhiteSpace($Version)) {
    $Version = "dev"
}

if (-not (Test-Path -LiteralPath $distPath)) {
    throw "dist directory not found: $distPath"
}

if ($Clean -and (Test-Path -LiteralPath $outPath)) {
    $resolvedOut = Assert-InRepository -Path $outPath
    Remove-Item -LiteralPath $resolvedOut -Recurse -Force
}
New-Item -ItemType Directory -Path $outPath -Force | Out-Null

$tempRoot = Join-Path $outPath "_tmp"
if (Test-Path -LiteralPath $tempRoot) {
    Remove-Item -LiteralPath $tempRoot -Recurse -Force
}
New-Item -ItemType Directory -Path $tempRoot -Force | Out-Null

$targets = @(
    @{ OS = "windows"; Arch = "amd64"; Format = "zip"; Extension = ".exe" },
    @{ OS = "linux"; Arch = "amd64"; Format = "tar.gz"; Extension = "" },
    @{ OS = "darwin"; Arch = "amd64"; Format = "tar.gz"; Extension = "" },
    @{ OS = "darwin"; Arch = "arm64"; Format = "tar.gz"; Extension = "" }
)

try {
    foreach ($target in $targets) {
        $os = $target.OS
        $arch = $target.Arch
        $extension = $target.Extension
        $packageName = "gophkeeper-$Version-$os-$arch"
        $packagePath = Join-Path $tempRoot $packageName
        New-Item -ItemType Directory -Path $packagePath -Force | Out-Null

        $clientBinary = Join-Path $distPath ("gk-$os-$arch$extension")
        $serverBinary = Join-Path $distPath ("gk-server-$os-$arch$extension")
        if (-not (Test-Path -LiteralPath $clientBinary)) {
            throw "client binary not found: $clientBinary"
        }
        if (-not (Test-Path -LiteralPath $serverBinary)) {
            throw "server binary not found: $serverBinary"
        }

        Copy-Item -LiteralPath $clientBinary -Destination (Join-Path $packagePath "gk$extension")
        Copy-Item -LiteralPath $serverBinary -Destination (Join-Path $packagePath "gk-server$extension")
        Copy-IfExists -Source (Join-Path $repoRoot "README.md") -Destination $packagePath
        Copy-IfExists -Source (Join-Path $repoRoot "README.en.md") -Destination $packagePath
        Copy-IfExists -Source (Join-Path $repoRoot "api") -Destination $packagePath

        if ($target.Format -eq "zip") {
            $archive = Join-Path $outPath "$packageName.zip"
            if (Test-Path -LiteralPath $archive) {
                Remove-Item -LiteralPath $archive -Force
            }
            Compress-Archive -Path (Join-Path $packagePath "*") -DestinationPath $archive
        } else {
            $archive = Join-Path $outPath "$packageName.tar.gz"
            if (Test-Path -LiteralPath $archive) {
                Remove-Item -LiteralPath $archive -Force
            }
            Push-Location $tempRoot
            try {
                & tar -czf $archive $packageName
                if ($LASTEXITCODE -ne 0) {
                    throw "tar failed for $packageName"
                }
            } finally {
                Pop-Location
            }
        }
        Write-Host "packaged $archive"
    }
} finally {
    if (Test-Path -LiteralPath $tempRoot) {
        Remove-Item -LiteralPath $tempRoot -Recurse -Force
    }
}

$checksumPath = Join-Path $outPath "checksums.txt"
$checksumLines = Get-ChildItem -LiteralPath $outPath -File |
    Where-Object { $_.Name -ne "checksums.txt" } |
    Sort-Object Name |
    ForEach-Object {
        $hash = Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256
        "{0}  {1}" -f $hash.Hash.ToLowerInvariant(), $_.Name
    }
Set-Content -LiteralPath $checksumPath -Value $checksumLines -Encoding ascii

Write-Host "release packages written to $outPath"
