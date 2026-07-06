package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

const createMigrationTableSQL = `CREATE TABLE IF NOT EXISTS schema_migrations (
    version BIGINT PRIMARY KEY,
    name TEXT NOT NULL,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
)`

const selectAppliedMigrationVersionsSQL = `SELECT version FROM schema_migrations`
const insertMigrationSQL = `INSERT INTO schema_migrations (version, name) VALUES ($1, $2)`

var upMigrationNamePattern = regexp.MustCompile(`^(\d+)_(.+)\.up\.sql$`)

// Migration describes one SQL migration file.
type Migration struct {
	Version int
	Name    string
	SQL     string
}

// MigrateUp applies all pending up migrations from source.
func MigrateUp(ctx context.Context, db *sql.DB, source fs.FS) error {
	if db == nil {
		return errors.New("postgres migrate: db is nil")
	}
	if source == nil {
		return errors.New("postgres migrate: source fs is nil")
	}

	migrations, err := LoadUpMigrations(source)
	if err != nil {
		return err
	}

	if _, err = db.ExecContext(ctx, createMigrationTableSQL); err != nil {
		return fmt.Errorf("create schema_migrations table: %w", err)
	}

	applied, err := appliedMigrationVersions(ctx, db)
	if err != nil {
		return err
	}

	for _, migration := range migrations {
		if applied[migration.Version] {
			continue
		}
		if err = applyMigration(ctx, db, migration); err != nil {
			return err
		}
	}

	return nil
}

// LoadUpMigrations reads up migrations from source and returns them sorted by version.
func LoadUpMigrations(source fs.FS) ([]Migration, error) {
	if source == nil {
		return nil, errors.New("postgres migrations: source fs is nil")
	}

	entries, err := fs.ReadDir(source, ".")
	if err != nil {
		return nil, fmt.Errorf("read migrations: %w", err)
	}

	migrations := make([]Migration, 0, len(entries))
	seen := make(map[int]string)
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		filename := filepath.ToSlash(entry.Name())
		matches := upMigrationNamePattern.FindStringSubmatch(filename)
		if matches == nil {
			continue
		}

		version, err := strconv.Atoi(matches[1])
		if err != nil {
			return nil, fmt.Errorf("parse migration version %q: %w", matches[1], err)
		}
		name := strings.ReplaceAll(matches[2], "_", " ")
		if previous, ok := seen[version]; ok {
			return nil, fmt.Errorf("duplicate migration version %d: %q and %q", version, previous, filename)
		}
		seen[version] = filename

		data, err := fs.ReadFile(source, filename)
		if err != nil {
			return nil, fmt.Errorf("read migration %q: %w", filename, err)
		}

		sqlText := strings.TrimSpace(string(data))
		if sqlText == "" {
			return nil, fmt.Errorf("migration %q is empty", filename)
		}

		migrations = append(migrations, Migration{
			Version: version,
			Name:    name,
			SQL:     sqlText,
		})
	}

	sort.Slice(migrations, func(i, j int) bool {
		return migrations[i].Version < migrations[j].Version
	})

	return migrations, nil
}

func appliedMigrationVersions(ctx context.Context, db *sql.DB) (map[int]bool, error) {
	rows, err := db.QueryContext(ctx, selectAppliedMigrationVersionsSQL)
	if err != nil {
		return nil, fmt.Errorf("read applied migrations: %w", err)
	}
	defer func() {
		_ = rows.Close()
	}()

	applied := make(map[int]bool)
	for rows.Next() {
		var version int
		if err = rows.Scan(&version); err != nil {
			return nil, fmt.Errorf("scan applied migration: %w", err)
		}
		applied[version] = true
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate applied migrations: %w", err)
	}

	return applied, nil
}

func applyMigration(ctx context.Context, db *sql.DB, migration Migration) (err error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin migration %d: %w", migration.Version, err)
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	if _, err = tx.ExecContext(ctx, migration.SQL); err != nil {
		return fmt.Errorf("apply migration %d: %w", migration.Version, err)
	}
	if _, err = tx.ExecContext(ctx, insertMigrationSQL, migration.Version, migration.Name); err != nil {
		return fmt.Errorf("record migration %d: %w", migration.Version, err)
	}
	if err = tx.Commit(); err != nil {
		return fmt.Errorf("commit migration %d: %w", migration.Version, err)
	}

	return nil
}
