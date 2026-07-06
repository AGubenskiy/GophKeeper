// Package migrations embeds SQL migrations for the GophKeeper server.
package migrations

import "embed"

// FS contains SQL migration files.
//
//go:embed *.sql
var FS embed.FS
