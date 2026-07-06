# GophKeeper

**Язык:** Русский | [English](README.en.md)

GophKeeper - менеджер секретов с CLI-клиентом и HTTP-сервером. Клиент шифрует данные локально, сервер хранит только ciphertext и синхронизирует записи между устройствами одного пользователя.

## Возможности

- Регистрация, вход, refresh/logout сессий.
- CLI-клиент для Windows, Linux и macOS.
- Локальное AES-GCM шифрование vault-записей до отправки на сервер.
- Типы записей: логин/пароль, текст, файл, банковская карта.
- Произвольные текстовые метаданные для каждой записи.
- PostgreSQL-backed серверное хранилище с миграциями.
- Push/pull синхронизация по revision, tombstones и явное разрешение конфликтов.
- OpenAPI-контракт: [api/openapi.yaml](api/openapi.yaml).
- Quality gate: tests, coverage, vet, staticcheck, govulncheck, doc comments.

## Требования

- Go 1.26+
- PostgreSQL 14+ для полноценного серверного режима.
- PowerShell для release/quality scripts на Windows.

## Быстрый Старт

Создайте пустую PostgreSQL-базу, например `gophkeeper_demo`, и запустите сервер:

```powershell
$env:GOPHKEEPER_DATABASE_DSN='postgres://user:password@localhost:5432/gophkeeper_demo?sslmode=disable'
$env:GOPHKEEPER_ACCESS_TOKEN_SECRET='12345678901234567890123456789012'
go run ./cmd/gk-server --address localhost:8080
```

Сервер применяет встроенные миграции при старте.

Проверьте сервер:

```powershell
curl http://localhost:8080/healthz
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\smoke-api.ps1 -ServerURL http://localhost:8080
```

Зарегистрируйте клиента и добавьте записи:

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

Команды, работающие с секретами, запрашивают значения через prompt. Используйте один и тот же мастер-пароль для одного аккаунта на всех клиентах.

## CLI

Основные команды:

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

Локальная SQLite-база клиента по умолчанию хранится в пользовательской config-директории. Для изолированного профиля используйте `--data-dir`.

## Синхронизация

`gk sync`:

- обновляет access token через refresh token при необходимости;
- отправляет локальные dirty upsert/delete записи;
- получает изменения после локального `last_revision`;
- сохраняет конфликты локально вместо silent overwrite.

Конфликт решается явно:

```powershell
go run ./cmd/gk --data-dir ./tmp/client conflict list
go run ./cmd/gk --data-dir ./tmp/client conflict keep-local ITEM_ID
go run ./cmd/gk --data-dir ./tmp/client conflict keep-remote ITEM_ID
go run ./cmd/gk --data-dir ./tmp/client sync
```

## HTTP API

Реализованные endpoints:

- `GET /healthz`
- `GET /version`
- `GET /api/v1/auth/params?login=...`
- `POST /api/v1/auth/register`
- `POST /api/v1/auth/login`
- `POST /api/v1/auth/refresh`
- `POST /api/v1/auth/logout`
- `GET /api/v1/sync/changes?since_revision=...`
- `POST /api/v1/sync/push`

Все ошибки возвращаются в стабильном формате:

```json
{
  "error": {
    "code": "validation_error",
    "message": "human-readable message",
    "request_id": "request-id"
  }
}
```

## Конфигурация Сервера

Флаги:

```text
--address
--database-dsn
--access-token-secret
--access-token-ttl
--refresh-token-ttl
--log-level
--shutdown-timeout
```

Переменные окружения:

```text
GOPHKEEPER_SERVER_ADDRESS
GOPHKEEPER_DATABASE_DSN
GOPHKEEPER_ACCESS_TOKEN_SECRET
GOPHKEEPER_ACCESS_TOKEN_TTL
GOPHKEEPER_REFRESH_TOKEN_TTL
GOPHKEEPER_SERVER_LOG_LEVEL
GOPHKEEPER_SERVER_SHUTDOWN_TIMEOUT
```

Auth/sync endpoints недоступны без `database-dsn` и token secret длиной не меньше 32 байт.

## Проверки

Быстрый тест:

```bash
go test ./...
```

Полный quality gate:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\check-quality.ps1 -InstallTools -CoverageThreshold 70
```

Скрипт проверяет форматирование, документацию экспортированных Go API, тесты, `go vet`, `staticcheck`, `govulncheck` и суммарное покрытие.

PostgreSQL integration tests:

```powershell
$env:GOPHKEEPER_TEST_POSTGRES_DSN='postgres://user:password@localhost:5432/gophkeeper_test?sslmode=disable'
go test ./internal/postgres
Remove-Item Env:\GOPHKEEPER_TEST_POSTGRES_DSN
```

## Сборка

Обычная сборка:

```bash
go build ./cmd/gk ./cmd/gk-server
```

Сборка release artifacts:

```powershell
.\scripts\build-release.ps1 -Version 0.1.0 -Commit abc123 -Clean
```

Скрипт собирает `gk` и `gk-server` для Windows amd64, Linux amd64, macOS amd64 и macOS arm64, добавляет build metadata и пишет SHA256 checksums в `dist/checksums.txt`.

Проверить build metadata:

```bash
gk version
gk-server version
curl http://localhost:8080/version
```

## Модель Безопасности

- Мастер-пароль не отправляется на сервер.
- Authentication secret выводится на клиенте и проверяется сервером через отдельный verifier.
- Vault key выводится локально и не покидает клиент.
- Сервер хранит encrypted payload, nonce, payload version и revision metadata.
- Payload шифруется AES-256-GCM с associated data, привязанными к user/item/version context.
- Refresh tokens хранятся сервером как hashes.
