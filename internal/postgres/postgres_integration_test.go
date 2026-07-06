package postgres_test

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"

	"github.com/AGubenskiy/GophKeeper/internal/postgres"
	"github.com/AGubenskiy/GophKeeper/migrations"
	_ "github.com/jackc/pgx/v5/stdlib"
)

func TestMigrateUpIntegration(t *testing.T) {
	dsn := os.Getenv("GOPHKEEPER_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("set GOPHKEEPER_TEST_POSTGRES_DSN to run PostgreSQL integration tests")
	}

	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("open postgres: %v", err)
	}
	defer func() {
		_ = db.Close()
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err = db.PingContext(ctx); err != nil {
		t.Fatalf("ping postgres: %v", err)
	}
	if err = postgres.MigrateUp(ctx, db, migrations.FS); err != nil {
		t.Fatalf("MigrateUp returned error: %v", err)
	}
}
