# GophKeeper

**Language:** [Русский](README.md) | English

GophKeeper is a secret manager with a CLI client and an HTTP server. The client encrypts data locally, while the server stores ciphertext only and synchronizes vault items between a user's devices.

## Features

- Registration, login, session refresh, and logout.
- CLI client for Windows, Linux, and macOS.
- Local AES-GCM encryption before any vault data reaches the server.
- Item types: login/password, text, file, bank card.
- Arbitrary text metadata on every item.
- PostgreSQL-backed server storage with migrations.
- Revision-based push/pull sync, tombstones, and explicit conflict resolution.
- OpenAPI contract: [api/openapi.yaml](api/openapi.yaml).
- Quality gate: tests, coverage, vet, staticcheck, govulncheck, doc comments.

## Requirements

- Go 1.26+
- PostgreSQL 14+ for the full server mode.
- PowerShell for release/quality scripts on Windows.

## Quick Start

Create an empty PostgreSQL database, for example `gophkeeper_demo`, and start the server:

```powershell
$env:GOPHKEEPER_DATABASE_DSN='postgres://user:password@localhost:5432/gophkeeper_demo?sslmode=disable'
$env:GOPHKEEPER_ACCESS_TOKEN_SECRET='12345678901234567890123456789012'
go run ./cmd/gk-server --address localhost:8080
```

The server applies embedded migrations on startup.

Check the server:

```powershell
curl http://localhost:8080/healthz
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\smoke-api.ps1 -ServerURL http://localhost:8080
```

Register a client and add items:

```powershell
$server = 'http://localhost:8080'
$login = 'alice'
$dataDir = './tmp/gophkeeper-client'

go run ./cmd/gk --data-dir $dataDir register --server $server --login $login
go run ./cmd/gk --data-dir $dataDir add password --title GitHub --login alice --meta url=https://github.com
go run ./cmd/gk --data-dir $dataDir add text --title "Recovery note" --text "stored encrypted locally"
go run ./cmd/gk --data-dir $dataDir list
go run ./cmd/gk --data-dir $dataDir sync
```

Commands that handle secrets prompt for values interactively. Use the same master password for the same account on every client.

## CLI

Main commands:

```text
gk version
gk register --server URL --login LOGIN
gk login [--server URL --login LOGIN]
gk logout
gk status

gk add password --title TITLE --login LOGIN
gk add text --title TITLE --text TEXT
gk add card --title TITLE --number NUMBER --expiry EXPIRY
gk add file --title TITLE --path PATH

gk list [--kind password|text|card|file]
gk show ITEM_ID [--reveal] [--export PATH]
gk edit ITEM_ID
gk delete ITEM_ID
gk sync

gk conflict list
gk conflict keep-local ITEM_ID
gk conflict keep-remote ITEM_ID
```

The local client SQLite database is stored under the user's config directory by default. Use `--data-dir` for an isolated profile.

## Synchronization

`gk sync`:

- refreshes the access token when needed;
- pushes local dirty upsert/delete items;
- pulls server changes after the local `last_revision`;
- stores conflicts locally instead of silently overwriting data.

Resolve conflicts explicitly:

```powershell
go run ./cmd/gk --data-dir ./tmp/client conflict list
go run ./cmd/gk --data-dir ./tmp/client conflict keep-local ITEM_ID
go run ./cmd/gk --data-dir ./tmp/client conflict keep-remote ITEM_ID
go run ./cmd/gk --data-dir ./tmp/client sync
```

## HTTP API

Implemented endpoints:

- `GET /healthz`
- `GET /version`
- `GET /api/v1/auth/params?login=...`
- `POST /api/v1/auth/register`
- `POST /api/v1/auth/login`
- `POST /api/v1/auth/refresh`
- `POST /api/v1/auth/logout`
- `GET /api/v1/sync/changes?since_revision=...`
- `POST /api/v1/sync/push`

All errors use a stable envelope:

```json
{
  "error": {
    "code": "validation_error",
    "message": "human-readable message",
    "request_id": "request-id"
  }
}
```

## Server Configuration

Flags:

```text
--address
--database-dsn
--access-token-secret
--access-token-ttl
--refresh-token-ttl
--log-level
--shutdown-timeout
```

Environment variables:

```text
GOPHKEEPER_SERVER_ADDRESS
GOPHKEEPER_DATABASE_DSN
GOPHKEEPER_ACCESS_TOKEN_SECRET
GOPHKEEPER_ACCESS_TOKEN_TTL
GOPHKEEPER_REFRESH_TOKEN_TTL
GOPHKEEPER_SERVER_LOG_LEVEL
GOPHKEEPER_SERVER_SHUTDOWN_TIMEOUT
```

Auth/sync endpoints are unavailable without a database DSN and a token secret of at least 32 bytes.

## Checks

Fast test run:

```bash
go test ./...
```

Full quality gate:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\check-quality.ps1 -InstallTools -CoverageThreshold 70
```

The script checks formatting, exported Go API documentation, tests, `go vet`, `staticcheck`, `govulncheck`, and total coverage.

PostgreSQL integration tests:

```powershell
$env:GOPHKEEPER_TEST_POSTGRES_DSN='postgres://user:password@localhost:5432/gophkeeper_test?sslmode=disable'
go test ./internal/postgres
Remove-Item Env:\GOPHKEEPER_TEST_POSTGRES_DSN
```

## Build

Standard build:

```bash
go build ./cmd/gk ./cmd/gk-server
```

Build release artifacts:

```powershell
.\scripts\build-release.ps1 -Version 0.1.0 -Commit abc123 -Clean
```

The script builds `gk` and `gk-server` for Windows amd64, Linux amd64, macOS amd64, and macOS arm64, injects build metadata, and writes SHA256 checksums to `dist/checksums.txt`.

Check build metadata:

```bash
gk version
gk-server version
curl http://localhost:8080/version
```

## Security Model

- The master password is never sent to the server.
- The authentication secret is derived client-side and verified server-side through a separate verifier.
- The vault key is derived locally and never leaves the client.
- The server stores encrypted payloads, nonces, payload versions, and revision metadata.
- Payloads are encrypted with AES-256-GCM and associated data bound to user/item/version context.
- Refresh tokens are stored server-side as hashes.
