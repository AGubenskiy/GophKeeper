param(
    [string]$Version = "",
    [string]$BuildDate = "",
    [string]$Commit = "",
    [string]$DistDir = "dist",
    [string[]]$Targets = @("windows/amd64", "linux/amd64", "darwin/amd64", "darwin/arm64"),
    [switch]$Clean
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Get-GitValue {
    param(
        [string[]]$Arguments,
        [string]$Fallback
    )

    try {
        $value = & git @Arguments 2>$null
        if ($LASTEXITCODE -eq 0 -and -not [string]::IsNullOrWhiteSpace($value)) {
            return ($value | Select-Object -First 1).Trim()
        }
    } catch {
    }
    return $Fallback
}

function Assert-SupportedTarget {
    param([string]$Target)

    $parts = $Target.Split("/")
    if ($parts.Count -ne 2 -or [string]::IsNullOrWhiteSpace($parts[0]) -or [string]::IsNullOrWhiteSpace($parts[1])) {
        throw "target must use GOOS/GOARCH form, got '$Target'"
    }

    $supported = @(
        "windows/amd64",
        "linux/amd64",
        "darwin/amd64",
        "darwin/arm64"
    )
    if ($supported -notcontains $Target) {
        throw "unsupported target '$Target'"
    }
}

$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = (Resolve-Path -LiteralPath (Join-Path $scriptRoot "..")).Path
$distPath = Join-Path $repoRoot $DistDir

if ([string]::IsNullOrWhiteSpace($Version)) {
    $Version = Get-GitValue -Arguments @("describe", "--tags", "--always", "--dirty") -Fallback "dev"
}
if ([string]::IsNullOrWhiteSpace($Commit)) {
    $Commit = Get-GitValue -Arguments @("rev-parse", "--short", "HEAD") -Fallback "none"
}
if ([string]::IsNullOrWhiteSpace($BuildDate)) {
    $BuildDate = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
}

if ($Clean -and (Test-Path -LiteralPath $distPath)) {
    $resolvedDist = (Resolve-Path -LiteralPath $distPath).Path
    $repoRootPrefix = $repoRoot
    if (-not $repoRootPrefix.EndsWith([System.IO.Path]::DirectorySeparatorChar)) {
        $repoRootPrefix += [System.IO.Path]::DirectorySeparatorChar
    }
    if ($resolvedDist -eq $repoRoot -or -not $resolvedDist.StartsWith($repoRootPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "refusing to clean path outside repository: $resolvedDist"
    }
    Remove-Item -LiteralPath $resolvedDist -Recurse -Force
}
New-Item -ItemType Directory -Path $distPath -Force | Out-Null

$commands = @(
    @{ Name = "gk"; Package = "./cmd/gk" },
    @{ Name = "gk-server"; Package = "./cmd/gk-server" }
)

$oldGOOS = $env:GOOS
$oldGOARCH = $env:GOARCH
$oldCGO = $env:CGO_ENABLED

try {
    $env:CGO_ENABLED = "0"
    $ldflags = "-s -w -X main.version=$Version -X main.buildDate=$BuildDate -X main.commit=$Commit"

    Push-Location $repoRoot
    try {
        foreach ($target in $Targets) {
            Assert-SupportedTarget -Target $target
            $parts = $target.Split("/")
            $env:GOOS = $parts[0]
            $env:GOARCH = $parts[1]
            $suffix = ""
            if ($env:GOOS -eq "windows") {
                $suffix = ".exe"
            }

            foreach ($command in $commands) {
                $fileName = "{0}-{1}-{2}{3}" -f $command.Name, $env:GOOS, $env:GOARCH, $suffix
                $output = Join-Path $distPath $fileName
                Write-Host "building $fileName"
                & go build -trimpath -ldflags $ldflags -o $output $command.Package
            }
        }
    } finally {
        Pop-Location
    }
} finally {
    $env:GOOS = $oldGOOS
    $env:GOARCH = $oldGOARCH
    $env:CGO_ENABLED = $oldCGO
}

$checksumPath = Join-Path $distPath "checksums.txt"
$checksumLines = Get-ChildItem -LiteralPath $distPath -File |
    Where-Object { $_.Name -ne "checksums.txt" } |
    Sort-Object Name |
    ForEach-Object {
        $hash = Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256
        "{0}  {1}" -f $hash.Hash.ToLowerInvariant(), $_.Name
    }
Set-Content -LiteralPath $checksumPath -Value $checksumLines -Encoding ascii

Write-Host "release artifacts written to $distPath"
