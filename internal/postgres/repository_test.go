package postgres

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/AGubenskiy/GophKeeper/internal/domain"
	"github.com/AGubenskiy/GophKeeper/internal/syncsvc"
	"github.com/DATA-DOG/go-sqlmock"
)

func TestUserRepositoryCreate(t *testing.T) {
	db, mock := newSQLMock(t)
	repo := NewUserRepository(db)
	user := testUser()

	mock.ExpectBegin()
	mock.ExpectExec(`INSERT INTO users (id, login, auth_salt, vault_salt, auth_secret_hash, kdf_params, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7, $8)`).
		WithArgs(user.ID, user.Login, user.AuthSalt, user.VaultSalt, user.AuthSecretHash, []byte(user.KDFParams), user.CreatedAt, user.UpdatedAt).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`INSERT INTO user_sync_state (user_id, current_revision) VALUES ($1, 0)`).
		WithArgs(user.ID).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	if err := repo.Create(context.Background(), user); err != nil {
		t.Fatalf("Create returned error: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet sql expectations: %v", err)
	}
}

func TestUserRepositoryFindByLogin(t *testing.T) {
	db, mock := newSQLMock(t)
	repo := NewUserRepository(db)
	user := testUser()

	mock.ExpectQuery(selectUserSQL + ` WHERE login = $1`).
		WithArgs(user.Login).
		WillReturnRows(userRows(user))

	got, err := repo.FindByLogin(context.Background(), user.Login)
	if err != nil {
		t.Fatalf("FindByLogin returned error: %v", err)
	}
	if got.ID != user.ID || got.Login != user.Login {
		t.Fatalf("FindByLogin = %+v, want user %+v", got, user)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet sql expectations: %v", err)
	}
}

func TestUserRepositoryFindByID(t *testing.T) {
	db, mock := newSQLMock(t)
	repo := NewUserRepository(db)
	user := testUser()

	mock.ExpectQuery(selectUserSQL + ` WHERE id = $1`).
		WithArgs(user.ID).
		WillReturnRows(userRows(user))

	got, err := repo.FindByID(context.Background(), user.ID)
	if err != nil {
		t.Fatalf("FindByID returned error: %v", err)
	}
	if got.ID != user.ID {
		t.Fatalf("FindByID ID = %q, want %q", got.ID, user.ID)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet sql expectations: %v", err)
	}
}

func TestUserRepositoryFindByLoginMapsNotFound(t *testing.T) {
	db, mock := newSQLMock(t)
	repo := NewUserRepository(db)

	mock.ExpectQuery(selectUserSQL + ` WHERE login = $1`).
		WithArgs("missing").
		WillReturnError(sql.ErrNoRows)

	_, err := repo.FindByLogin(context.Background(), "missing")
	if !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("FindByLogin error = %v, want ErrNotFound", err)
	}
}

func TestRepositoriesRejectNilDB(t *testing.T) {
	if _, err := NewUserRepository(nil).FindByID(context.Background(), "user-1"); err == nil {
		t.Fatal("FindByID returned nil error for nil db")
	}
	if err := NewRefreshTokenRepository(nil).Create(context.Background(), testRefreshToken()); err == nil {
		t.Fatal("Create refresh token returned nil error for nil db")
	}
	if err := NewVaultItemRepository(nil).Upsert(context.Background(), testVaultItem()); err == nil {
		t.Fatal("Upsert vault item returned nil error for nil db")
	}
	if _, err := NewSyncStateRepository(nil).Get(context.Background(), "user-1"); err == nil {
		t.Fatal("Get sync state returned nil error for nil db")
	}
}

func TestRefreshTokenRepositoryCreateAndFind(t *testing.T) {
	db, mock := newSQLMock(t)
	repo := NewRefreshTokenRepository(db)
	token := testRefreshToken()

	mock.ExpectExec(`INSERT INTO refresh_tokens (id, user_id, token_hash, client_id, expires_at, revoked_at, created_at)
VALUES ($1, $2, $3, $4, $5, $6, $7)`).
		WithArgs(token.ID, token.UserID, token.TokenHash, token.ClientID, token.ExpiresAt, token.RevokedAt, token.CreatedAt).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery(selectRefreshTokenSQL + ` WHERE token_hash = $1`).
		WithArgs(token.TokenHash).
		WillReturnRows(refreshTokenRows(token))

	if err := repo.Create(context.Background(), token); err != nil {
		t.Fatalf("Create returned error: %v", err)
	}

	got, err := repo.FindByHash(context.Background(), token.TokenHash)
	if err != nil {
		t.Fatalf("FindByHash returned error: %v", err)
	}
	if got.ID != token.ID || got.UserID != token.UserID {
		t.Fatalf("FindByHash = %+v, want token %+v", got, token)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet sql expectations: %v", err)
	}
}

func TestRefreshTokenRepositoryFindByHashRejectsEmptyHash(t *testing.T) {
	db, _ := newSQLMock(t)
	repo := NewRefreshTokenRepository(db)

	_, err := repo.FindByHash(context.Background(), nil)
	if !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("FindByHash error = %v, want ErrValidation", err)
	}
}

func TestRefreshTokenRepositoryRevoke(t *testing.T) {
	db, mock := newSQLMock(t)
	repo := NewRefreshTokenRepository(db)
	revokedAt := testTime().Add(time.Minute)

	mock.ExpectExec(`UPDATE refresh_tokens SET revoked_at = $2 WHERE id = $1 AND revoked_at IS NULL`).
		WithArgs("token-1", revokedAt).
		WillReturnResult(sqlmock.NewResult(0, 1))

	if err := repo.Revoke(context.Background(), "token-1", revokedAt); err != nil {
		t.Fatalf("Revoke returned error: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet sql expectations: %v", err)
	}
}

func TestRefreshTokenRepositoryRevokeMapsNoRows(t *testing.T) {
	db, mock := newSQLMock(t)
	repo := NewRefreshTokenRepository(db)
	revokedAt := testTime().Add(time.Minute)

	mock.ExpectExec(`UPDATE refresh_tokens SET revoked_at = $2 WHERE id = $1 AND revoked_at IS NULL`).
		WithArgs("token-1", revokedAt).
		WillReturnResult(sqlmock.NewResult(0, 0))

	err := repo.Revoke(context.Background(), "token-1", revokedAt)
	if !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("Revoke error = %v, want ErrNotFound", err)
	}
}

func TestVaultItemRepositoryUpsertFindAndListChanged(t *testing.T) {
	db, mock := newSQLMock(t)
	repo := NewVaultItemRepository(db)
	item := testVaultItem()

	mock.ExpectExec(`INSERT INTO vault_items (id, user_id, server_revision, encrypted_payload, payload_nonce, payload_version, deleted_at, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
ON CONFLICT (user_id, id) DO UPDATE SET
    server_revision = EXCLUDED.server_revision,
    encrypted_payload = EXCLUDED.encrypted_payload,
    payload_nonce = EXCLUDED.payload_nonce,
    payload_version = EXCLUDED.payload_version,
    deleted_at = EXCLUDED.deleted_at,
    updated_at = EXCLUDED.updated_at`).
		WithArgs(item.ID, item.UserID, item.ServerRevision, item.EncryptedPayload, item.PayloadNonce, item.PayloadVersion, item.DeletedAt, item.CreatedAt, item.UpdatedAt).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery(selectVaultItemSQL+` WHERE user_id = $1 AND id = $2`).
		WithArgs(item.UserID, item.ID).
		WillReturnRows(vaultItemRows(item))
	mock.ExpectQuery(selectVaultItemSQL+` WHERE user_id = $1 AND server_revision > $2 ORDER BY server_revision ASC LIMIT $3`).
		WithArgs(item.UserID, int64(0), 10).
		WillReturnRows(vaultItemRows(item))

	if err := repo.Upsert(context.Background(), item); err != nil {
		t.Fatalf("Upsert returned error: %v", err)
	}
	if _, err := repo.Find(context.Background(), item.UserID, item.ID); err != nil {
		t.Fatalf("Find returned error: %v", err)
	}
	items, err := repo.ListChanged(context.Background(), item.UserID, 0, 10)
	if err != nil {
		t.Fatalf("ListChanged returned error: %v", err)
	}
	if len(items) != 1 || items[0].ID != item.ID {
		t.Fatalf("ListChanged = %+v, want one item", items)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet sql expectations: %v", err)
	}
}

func TestVaultItemRepositoryListChangedUsesDefaultLimit(t *testing.T) {
	db, mock := newSQLMock(t)
	repo := NewVaultItemRepository(db)
	item := testVaultItem()

	mock.ExpectQuery(selectVaultItemSQL+` WHERE user_id = $1 AND server_revision > $2 ORDER BY server_revision ASC LIMIT $3`).
		WithArgs(item.UserID, int64(0), defaultListChangedLimit).
		WillReturnRows(vaultItemRows(item))

	items, err := repo.ListChanged(context.Background(), item.UserID, 0, 0)
	if err != nil {
		t.Fatalf("ListChanged returned error: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("len(items) = %d, want 1", len(items))
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet sql expectations: %v", err)
	}
}

func TestVaultItemRepositorySoftDelete(t *testing.T) {
	db, mock := newSQLMock(t)
	repo := NewVaultItemRepository(db)
	item := testVaultItem()
	deletedAt := testTime().Add(time.Minute)
	item.DeletedAt = &deletedAt
	item.ServerRevision = 2
	item.UpdatedAt = deletedAt

	mock.ExpectQuery(`UPDATE vault_items
SET server_revision = $3, deleted_at = $4, updated_at = $4
WHERE user_id = $1 AND id = $2
RETURNING id, user_id, server_revision, encrypted_payload, payload_nonce, payload_version, deleted_at, created_at, updated_at`).
		WithArgs(item.UserID, item.ID, item.ServerRevision, deletedAt).
		WillReturnRows(vaultItemRows(item))

	got, err := repo.SoftDelete(context.Background(), item.UserID, item.ID, item.ServerRevision, deletedAt)
	if err != nil {
		t.Fatalf("SoftDelete returned error: %v", err)
	}
	if got.DeletedAt == nil || !got.DeletedAt.Equal(deletedAt) {
		t.Fatalf("DeletedAt = %v, want %v", got.DeletedAt, deletedAt)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet sql expectations: %v", err)
	}
}

func TestVaultItemRepositoryApplyMutationAtomically(t *testing.T) {
	db, mock := newSQLMock(t)
	repo := NewVaultItemRepository(db)
	now := testTime()
	mutation := syncsvc.Mutation{
		ID:               "item-1",
		BaseRevision:     0,
		EncryptedPayload: []byte("ciphertext"),
		PayloadNonce:     []byte("nonce"),
		PayloadVersion:   1,
	}
	expected := domain.VaultItem{
		ID:               "item-1",
		UserID:           "user-1",
		ServerRevision:   1,
		EncryptedPayload: []byte("ciphertext"),
		PayloadNonce:     []byte("nonce"),
		PayloadVersion:   1,
		CreatedAt:        now,
		UpdatedAt:        now,
	}

	mock.ExpectBegin()
	mock.ExpectQuery(selectVaultItemSQL+` WHERE user_id = $1 AND id = $2 FOR UPDATE`).
		WithArgs("user-1", "item-1").
		WillReturnError(sql.ErrNoRows)
	mock.ExpectQuery(`UPDATE user_sync_state
SET current_revision = current_revision + 1
WHERE user_id = $1
RETURNING current_revision`).
		WithArgs("user-1").
		WillReturnRows(sqlmock.NewRows([]string{"current_revision"}).AddRow(int64(1)))
	mock.ExpectExec(upsertVaultItemSQL).
		WithArgs(expected.ID, expected.UserID, expected.ServerRevision, expected.EncryptedPayload, expected.PayloadNonce, expected.PayloadVersion, expected.DeletedAt, expected.CreatedAt, expected.UpdatedAt).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	got, conflict, err := repo.ApplyMutation(context.Background(), "user-1", mutation, now)
	if err != nil {
		t.Fatalf("ApplyMutation returned error: %v", err)
	}
	if conflict != nil {
		t.Fatalf("conflict = %+v, want nil", conflict)
	}
	if got.ServerRevision != 1 || got.UserID != "user-1" || string(got.EncryptedPayload) != "ciphertext" {
		t.Fatalf("ApplyMutation = %+v, want applied item", got)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet sql expectations: %v", err)
	}
}

func TestVaultItemRepositoryApplyMutationReturnsConflictBeforeIncrement(t *testing.T) {
	db, mock := newSQLMock(t)
	repo := NewVaultItemRepository(db)
	current := testVaultItem()
	current.ServerRevision = 7

	mock.ExpectBegin()
	mock.ExpectQuery(selectVaultItemSQL+` WHERE user_id = $1 AND id = $2 FOR UPDATE`).
		WithArgs(current.UserID, current.ID).
		WillReturnRows(vaultItemRows(current))
	mock.ExpectRollback()

	_, conflict, err := repo.ApplyMutation(context.Background(), current.UserID, syncsvc.Mutation{
		ID:               current.ID,
		BaseRevision:     3,
		EncryptedPayload: []byte("ciphertext"),
		PayloadNonce:     []byte("nonce"),
		PayloadVersion:   1,
	}, testTime())
	if err != nil {
		t.Fatalf("ApplyMutation returned error: %v", err)
	}
	if conflict == nil || conflict.ServerRevision != 7 || conflict.Remote == nil {
		t.Fatalf("conflict = %+v, want remote revision conflict", conflict)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet sql expectations: %v", err)
	}
}

func TestSyncStateRepositoryIncrementMapsNotFound(t *testing.T) {
	db, mock := newSQLMock(t)
	repo := NewSyncStateRepository(db)

	mock.ExpectQuery(`UPDATE user_sync_state
SET current_revision = current_revision + 1
WHERE user_id = $1
RETURNING current_revision`).
		WithArgs("user-1").
		WillReturnError(sql.ErrNoRows)

	_, err := repo.Increment(context.Background(), "user-1")
	if !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("Increment error = %v, want ErrNotFound", err)
	}
}

func TestSyncStateRepositoryGetSetAndIncrement(t *testing.T) {
	db, mock := newSQLMock(t)
	repo := NewSyncStateRepository(db)
	state := domain.SyncState{UserID: "user-1", CurrentRevision: 3}

	mock.ExpectExec(`INSERT INTO user_sync_state (user_id, current_revision) VALUES ($1, $2)
ON CONFLICT (user_id) DO UPDATE SET current_revision = EXCLUDED.current_revision`).
		WithArgs(state.UserID, state.CurrentRevision).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery(`SELECT user_id, current_revision FROM user_sync_state WHERE user_id = $1`).
		WithArgs(state.UserID).
		WillReturnRows(sqlmock.NewRows([]string{"user_id", "current_revision"}).AddRow(state.UserID, state.CurrentRevision))
	mock.ExpectQuery(`UPDATE user_sync_state
SET current_revision = current_revision + 1
WHERE user_id = $1
RETURNING current_revision`).
		WithArgs(state.UserID).
		WillReturnRows(sqlmock.NewRows([]string{"current_revision"}).AddRow(state.CurrentRevision + 1))

	if err := repo.Set(context.Background(), state); err != nil {
		t.Fatalf("Set returned error: %v", err)
	}
	got, err := repo.Get(context.Background(), state.UserID)
	if err != nil {
		t.Fatalf("Get returned error: %v", err)
	}
	if got != state {
		t.Fatalf("Get = %+v, want %+v", got, state)
	}
	revision, err := repo.Increment(context.Background(), state.UserID)
	if err != nil {
		t.Fatalf("Increment returned error: %v", err)
	}
	if revision != state.CurrentRevision+1 {
		t.Fatalf("Increment = %d, want %d", revision, state.CurrentRevision+1)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet sql expectations: %v", err)
	}
}

func newSQLMock(t *testing.T) (*sql.DB, sqlmock.Sqlmock) {
	t.Helper()

	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherEqual))
	if err != nil {
		t.Fatalf("create sqlmock: %v", err)
	}
	t.Cleanup(func() {
		_ = db.Close()
	})
	return db, mock
}

func testTime() time.Time {
	return time.Date(2026, 7, 2, 20, 0, 0, 0, time.UTC)
}

func testUser() domain.User {
	now := testTime()
	return domain.User{
		ID:             "user-1",
		Login:          "alice",
		AuthSalt:       []byte("auth-salt"),
		VaultSalt:      []byte("vault-salt"),
		AuthSecretHash: "hash",
		KDFParams:      []byte(`{"algorithm":"argon2id"}`),
		CreatedAt:      now,
		UpdatedAt:      now,
	}
}

func testRefreshToken() domain.RefreshToken {
	now := testTime()
	return domain.RefreshToken{
		ID:        "token-1",
		UserID:    "user-1",
		TokenHash: []byte("token-hash"),
		ClientID:  "client-1",
		ExpiresAt: now.Add(time.Hour),
		CreatedAt: now,
	}
}

func testVaultItem() domain.VaultItem {
	now := testTime()
	return domain.VaultItem{
		ID:               "item-1",
		UserID:           "user-1",
		ServerRevision:   1,
		EncryptedPayload: []byte("ciphertext"),
		PayloadNonce:     []byte("nonce"),
		PayloadVersion:   1,
		CreatedAt:        now,
		UpdatedAt:        now,
	}
}

func userRows(user domain.User) *sqlmock.Rows {
	return sqlmock.NewRows([]string{
		"id",
		"login",
		"auth_salt",
		"vault_salt",
		"auth_secret_hash",
		"kdf_params",
		"created_at",
		"updated_at",
	}).AddRow(
		user.ID,
		user.Login,
		user.AuthSalt,
		user.VaultSalt,
		user.AuthSecretHash,
		[]byte(user.KDFParams),
		user.CreatedAt,
		user.UpdatedAt,
	)
}

func refreshTokenRows(token domain.RefreshToken) *sqlmock.Rows {
	var revokedAt any
	if token.RevokedAt != nil {
		revokedAt = *token.RevokedAt
	}
	return sqlmock.NewRows([]string{
		"id",
		"user_id",
		"token_hash",
		"client_id",
		"expires_at",
		"revoked_at",
		"created_at",
	}).AddRow(
		token.ID,
		token.UserID,
		token.TokenHash,
		token.ClientID,
		token.ExpiresAt,
		revokedAt,
		token.CreatedAt,
	)
}

func vaultItemRows(item domain.VaultItem) *sqlmock.Rows {
	var deletedAt any
	if item.DeletedAt != nil {
		deletedAt = *item.DeletedAt
	}
	return sqlmock.NewRows([]string{
		"id",
		"user_id",
		"server_revision",
		"encrypted_payload",
		"payload_nonce",
		"payload_version",
		"deleted_at",
		"created_at",
		"updated_at",
	}).AddRow(
		item.ID,
		item.UserID,
		item.ServerRevision,
		item.EncryptedPayload,
		item.PayloadNonce,
		item.PayloadVersion,
		deletedAt,
		item.CreatedAt,
		item.UpdatedAt,
	)
}
