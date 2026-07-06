package postgres

import (
	"context"
	"errors"
	"io/fs"
	"testing"
	"testing/fstest"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestLoadUpMigrationsSortsAndNormalizesNames(t *testing.T) {
	source := fstest.MapFS{
		"000002_second_step.up.sql":  {Data: []byte("SELECT 2;")},
		"000001_first_step.up.sql":   {Data: []byte("SELECT 1;")},
		"000001_first_step.down.sql": {Data: []byte("SELECT 0;")},
	}

	migrations, err := LoadUpMigrations(source)
	if err != nil {
		t.Fatalf("LoadUpMigrations returned error: %v", err)
	}

	if len(migrations) != 2 {
		t.Fatalf("len(migrations) = %d, want 2", len(migrations))
	}
	if migrations[0].Version != 1 || migrations[0].Name != "first step" || migrations[0].SQL != "SELECT 1;" {
		t.Fatalf("first migration = %+v, want normalized version 1 migration", migrations[0])
	}
	if migrations[1].Version != 2 {
		t.Fatalf("second migration version = %d, want 2", migrations[1].Version)
	}
}

func TestLoadUpMigrationsRejectsDuplicateVersions(t *testing.T) {
	source := fstest.MapFS{
		"000001_first.up.sql": {Data: []byte("SELECT 1;")},
		"000001_other.up.sql": {Data: []byte("SELECT 2;")},
	}

	_, err := LoadUpMigrations(source)
	if err == nil {
		t.Fatal("LoadUpMigrations returned nil error, want duplicate version error")
	}
}

func TestLoadUpMigrationsRejectsEmptyMigration(t *testing.T) {
	source := fstest.MapFS{
		"000001_empty.up.sql": {Data: []byte("  \n")},
	}

	_, err := LoadUpMigrations(source)
	if err == nil {
		t.Fatal("LoadUpMigrations returned nil error, want empty migration error")
	}
}

func TestLoadUpMigrationsRejectsNilSource(t *testing.T) {
	_, err := LoadUpMigrations(nil)
	if err == nil {
		t.Fatal("LoadUpMigrations returned nil error, want nil source error")
	}
}

func TestLoadUpMigrationsWrapsReadDirError(t *testing.T) {
	_, err := LoadUpMigrations(errorFS{})
	if err == nil {
		t.Fatal("LoadUpMigrations returned nil error, want read error")
	}
}

func TestMigrateUpAppliesPendingMigrations(t *testing.T) {
	db, mock := newSQLMock(t)
	source := fstest.MapFS{
		"000001_first.up.sql":  {Data: []byte("SELECT 1;")},
		"000002_second.up.sql": {Data: []byte("SELECT 2;")},
	}

	mock.ExpectExec(createMigrationTableSQL).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(selectAppliedMigrationVersionsSQL).
		WillReturnRows(sqlmock.NewRows([]string{"version"}).AddRow(1))
	mock.ExpectBegin()
	mock.ExpectExec("SELECT 2;").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(insertMigrationSQL).WithArgs(2, "second").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	if err := MigrateUp(context.Background(), db, source); err != nil {
		t.Fatalf("MigrateUp returned error: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet sql expectations: %v", err)
	}
}

func TestMigrateUpRejectsNilInputs(t *testing.T) {
	if err := MigrateUp(context.Background(), nil, fstest.MapFS{}); err == nil {
		t.Fatal("MigrateUp returned nil error for nil db")
	}

	db, _ := newSQLMock(t)
	if err := MigrateUp(context.Background(), db, nil); err == nil {
		t.Fatal("MigrateUp returned nil error for nil source")
	}
}

func TestMigrateUpRollsBackFailedMigration(t *testing.T) {
	db, mock := newSQLMock(t)
	source := fstest.MapFS{
		"000001_first.up.sql": {Data: []byte("SELECT 1;")},
	}

	mock.ExpectExec(createMigrationTableSQL).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(selectAppliedMigrationVersionsSQL).
		WillReturnRows(sqlmock.NewRows([]string{"version"}))
	mock.ExpectBegin()
	mock.ExpectExec("SELECT 1;").WillReturnError(errors.New("boom"))
	mock.ExpectRollback()

	if err := MigrateUp(context.Background(), db, source); err == nil {
		t.Fatal("MigrateUp returned nil error, want migration failure")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet sql expectations: %v", err)
	}
}

type errorFS struct{}

func (errorFS) Open(string) (fs.File, error) {
	return nil, errors.New("open failed")
}
