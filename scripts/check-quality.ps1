param(
    [double]$CoverageThreshold = 70.0,
    [string]$CoverageProfile = "coverage.out",
    [string]$ToolsDir = ".tools/bin",
    [switch]$InstallTools,
    [switch]$Race,
    [switch]$KeepCoverage
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = (Resolve-Path -LiteralPath (Join-Path $scriptRoot "..")).Path
$toolsPath = Join-Path $repoRoot $ToolsDir
$coveragePath = Join-Path $repoRoot $CoverageProfile
$isWindowsOS = [System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform([System.Runtime.InteropServices.OSPlatform]::Windows)
$exeSuffix = ""
if ($isWindowsOS) {
    $exeSuffix = ".exe"
}

function Invoke-Step {
    param(
        [string]$Name,
        [scriptblock]$Command
    )

    Write-Host "==> $Name"
    & $Command
}

function Invoke-NativeCommand {
    param(
        [string]$FilePath,
        [string[]]$Arguments
    )

    & $FilePath @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$FilePath $($Arguments -join ' ') failed with exit code $LASTEXITCODE"
    }
}

function Get-RequiredTool {
    param(
        [string]$Name,
        [string]$Module
    )

    $localTool = Join-Path $toolsPath "$Name$exeSuffix"
    if (Test-Path -LiteralPath $localTool) {
        return $localTool
    }

    $pathTool = Get-Command $Name -ErrorAction SilentlyContinue
    if ($null -ne $pathTool) {
        return $pathTool.Source
    }

    if (-not $InstallTools) {
        throw "$Name is not installed. Re-run with -InstallTools to install it into $ToolsDir."
    }

    New-Item -ItemType Directory -Path $toolsPath -Force | Out-Null
    $oldGOBIN = $env:GOBIN
    try {
        $env:GOBIN = $toolsPath
        & go install $Module
        if ($LASTEXITCODE -ne 0) {
            throw "go install $Module failed"
        }
    } finally {
        $env:GOBIN = $oldGOBIN
    }

    if (-not (Test-Path -LiteralPath $localTool)) {
        throw "$Name was installed but was not found at $localTool"
    }
    return $localTool
}

Push-Location $repoRoot
try {
    Invoke-Step "gofmt check" {
        $goFiles = @()
        foreach ($dir in @("cmd", "internal", "migrations")) {
            $path = Join-Path $repoRoot $dir
            if (Test-Path -LiteralPath $path) {
                $goFiles += Get-ChildItem -LiteralPath $path -Recurse -Filter *.go -File | ForEach-Object { $_.FullName }
            }
        }
        if ($goFiles.Count -eq 0) {
            return
        }
        $unformatted = @(& gofmt -l @goFiles)
        if ($LASTEXITCODE -ne 0) {
            throw "gofmt failed with exit code $LASTEXITCODE"
        }
        if ($unformatted.Count -gt 0) {
            $unformatted | ForEach-Object { Write-Host "not gofmt-formatted: $_" }
            throw "gofmt check failed"
        }
    }

    Invoke-Step "go doc comments" {
        & (Join-Path $repoRoot "scripts/check-go-docs.ps1")
        if ($LASTEXITCODE -ne 0) {
            throw "go doc comments check failed"
        }
    }

    Invoke-Step "go test" {
        Invoke-NativeCommand -FilePath "go" -Arguments @("test", "./...")
    }

    Invoke-Step "go vet" {
        Invoke-NativeCommand -FilePath "go" -Arguments @("vet", "./...")
    }

    if ($Race) {
        Invoke-Step "go test -race" {
            Invoke-NativeCommand -FilePath "go" -Arguments @("test", "-race", "./...")
        }
    }

    $staticcheck = Get-RequiredTool -Name "staticcheck" -Module "honnef.co/go/tools/cmd/staticcheck@latest"
    Invoke-Step "staticcheck" {
        Invoke-NativeCommand -FilePath $staticcheck -Arguments @("./...")
    }

    $govulncheck = Get-RequiredTool -Name "govulncheck" -Module "golang.org/x/vuln/cmd/govulncheck@latest"
    Invoke-Step "govulncheck" {
        Invoke-NativeCommand -FilePath $govulncheck -Arguments @("./...")
    }

    Invoke-Step "coverage" {
        Invoke-NativeCommand -FilePath "go" -Arguments @("test", "./...", "-coverprofile=$coveragePath")
        $coverOutput = @(go tool cover -func $coveragePath)
        if ($LASTEXITCODE -ne 0) {
            throw "go tool cover failed with exit code $LASTEXITCODE"
        }
        $totalLine = ($coverOutput | Select-String -Pattern "^total:").Line
        if ([string]::IsNullOrWhiteSpace($totalLine)) {
            throw "coverage total line was not found"
        }
        if ($totalLine -notmatch "([0-9]+(?:\.[0-9]+)?)%$") {
            throw "cannot parse coverage total: $totalLine"
        }
        $total = [double]::Parse($Matches[1], [System.Globalization.CultureInfo]::InvariantCulture)
        if ($total -lt $CoverageThreshold) {
            throw ("coverage {0:n1}% is below required {1:n1}%" -f $total, $CoverageThreshold)
        }
        Write-Host ("coverage {0:n1}%" -f $total)
    }
} finally {
    Pop-Location
    if (-not $KeepCoverage -and (Test-Path -LiteralPath $coveragePath)) {
        Remove-Item -LiteralPath $coveragePath -Force
    }
}
