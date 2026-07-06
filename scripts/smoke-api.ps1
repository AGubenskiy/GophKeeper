param(
    [string]$ServerURL = "http://localhost:8080",
    [string]$LoginPrefix = "smoke",
    [int]$TimeoutSeconds = 10
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$baseURL = $ServerURL.TrimEnd("/")

function New-RandomBase64 {
    param([int]$Length)

    $bytes = [byte[]]::new($Length)
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $rng.GetBytes($bytes)
    } finally {
        $rng.Dispose()
    }
    return [Convert]::ToBase64String($bytes)
}

function Invoke-GophKeeperRequest {
    param(
        [string]$Method,
        [string]$Path,
        [object]$Body = $null,
        [string]$AccessToken = ""
    )

    $headers = @{}
    if (-not [string]::IsNullOrWhiteSpace($AccessToken)) {
        $headers["Authorization"] = "Bearer $AccessToken"
    }

    $arguments = @{
        Method     = $Method
        Uri        = "$baseURL$Path"
        Headers    = $headers
        TimeoutSec = $TimeoutSeconds
    }

    if ($null -ne $Body) {
        $arguments["Body"] = ($Body | ConvertTo-Json -Depth 8)
        $arguments["ContentType"] = "application/json"
    }

    try {
        return Invoke-RestMethod @arguments
    } catch {
        $details = $_.Exception.Message
        if ($_.ErrorDetails -and -not [string]::IsNullOrWhiteSpace($_.ErrorDetails.Message)) {
            $details = "$details $($_.ErrorDetails.Message)"
        }
        throw "$Method $Path failed: $details"
    }
}

function Assert-NotBlank {
    param(
        [string]$Name,
        [string]$Value
    )

    if ([string]::IsNullOrWhiteSpace($Value)) {
        throw "$Name is empty"
    }
}

Write-Host "==> health"
$health = Invoke-GophKeeperRequest -Method "GET" -Path "/healthz"
if ($health.status -ne "ok") {
    throw "unexpected health response: $($health | ConvertTo-Json -Compress)"
}

Write-Host "==> version"
$version = Invoke-GophKeeperRequest -Method "GET" -Path "/version"
Assert-NotBlank -Name "version" -Value $version.version

$suffix = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
$login = "$LoginPrefix-$suffix"
$clientID = [guid]::NewGuid().ToString()
$authSecret = New-RandomBase64 -Length 32

Write-Host "==> register $login"
$register = Invoke-GophKeeperRequest -Method "POST" -Path "/api/v1/auth/register" -Body @{
    login       = $login
    auth_secret = $authSecret
    client_id   = $clientID
}
Assert-NotBlank -Name "register access_token" -Value $register.access_token
Assert-NotBlank -Name "register refresh_token" -Value $register.refresh_token

Write-Host "==> auth params"
$encodedLogin = [uri]::EscapeDataString($login)
$params = Invoke-GophKeeperRequest -Method "GET" -Path "/api/v1/auth/params?login=$encodedLogin"
Assert-NotBlank -Name "auth_salt" -Value $params.auth_salt
Assert-NotBlank -Name "vault_salt" -Value $params.vault_salt

Write-Host "==> login"
$loginSession = Invoke-GophKeeperRequest -Method "POST" -Path "/api/v1/auth/login" -Body @{
    login       = $login
    auth_secret = $authSecret
    client_id   = $clientID
}
Assert-NotBlank -Name "login access_token" -Value $loginSession.access_token
Assert-NotBlank -Name "login refresh_token" -Value $loginSession.refresh_token

Write-Host "==> initial pull"
$initialPull = Invoke-GophKeeperRequest -Method "GET" -Path "/api/v1/sync/changes?since_revision=0" -AccessToken $loginSession.access_token
if ($initialPull.current_revision -lt 0) {
    throw "current_revision must be non-negative"
}

Write-Host "==> push encrypted item"
$itemID = [guid]::NewGuid().ToString()
$push = Invoke-GophKeeperRequest -Method "POST" -Path "/api/v1/sync/push" -AccessToken $loginSession.access_token -Body @{
    items = @(
        @{
            id                = $itemID
            base_revision     = 0
            encrypted_payload = New-RandomBase64 -Length 48
            payload_nonce     = New-RandomBase64 -Length 12
            payload_version   = 1
        }
    )
}
if ($push.applied.Count -ne 1) {
    throw "expected one applied item, got $($push.applied.Count)"
}

Write-Host "==> pull pushed item"
$pull = Invoke-GophKeeperRequest -Method "GET" -Path "/api/v1/sync/changes?since_revision=0" -AccessToken $loginSession.access_token
$pulledItem = @($pull.items | Where-Object { $_.id -eq $itemID })
if ($pulledItem.Count -ne 1) {
    throw "pushed item was not returned by pull"
}

Write-Host "==> refresh"
$refreshed = Invoke-GophKeeperRequest -Method "POST" -Path "/api/v1/auth/refresh" -Body @{
    refresh_token = $loginSession.refresh_token
}
Assert-NotBlank -Name "refreshed access_token" -Value $refreshed.access_token
Assert-NotBlank -Name "refreshed refresh_token" -Value $refreshed.refresh_token

Write-Host "==> logout"
$null = Invoke-GophKeeperRequest -Method "POST" -Path "/api/v1/auth/logout" -Body @{
    refresh_token = $refreshed.refresh_token
}
$null = Invoke-GophKeeperRequest -Method "POST" -Path "/api/v1/auth/logout" -Body @{
    refresh_token = $register.refresh_token
}

Write-Host "smoke ok: login=$login item=$itemID revision=$($push.current_revision)"
