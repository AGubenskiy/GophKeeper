package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/AGubenskiy/GophKeeper/internal/domain"
	"github.com/AGubenskiy/GophKeeper/internal/syncsvc"
)

const defaultListChangedLimit = 500

// UserRepository persists users in PostgreSQL.
type UserRepository struct {
	db *sql.DB
}

// NewUserRepository creates a user repository.
func NewUserRepository(db *sql.DB) *UserRepository {
	return &UserRepository{db: db}
}

// Create inserts a new user and initializes its sync state in one transaction.
func (r *UserRepository) Create(ctx context.Context, user domain.User) error {
	if err := ensureDB(r.db); err != nil {
		return err
	}
	if err := user.Validate(); err != nil {
		return err
	}

	now := time.Now().UTC()
	if user.CreatedAt.IsZero() {
		user.CreatedAt = now
	}
	if user.UpdatedAt.IsZero() {
		user.UpdatedAt = user.CreatedAt
	}

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin create user: %w", err)
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	if _, err = tx.ExecContext(
		ctx,
		`INSERT INTO users (id, login, auth_salt, vault_salt, auth_secret_hash, kdf_params, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7, $8)`,
		user.ID,
		user.Login,
		user.AuthSalt,
		user.VaultSalt,
		user.AuthSecretHash,
		[]byte(user.KDFParams),
		user.CreatedAt,
		user.UpdatedAt,
	); err != nil {
		return mapError(err)
	}

	if _, err = tx.ExecContext(
		ctx,
		`INSERT INTO user_sync_state (user_id, current_revision) VALUES ($1, 0)`,
		user.ID,
	); err != nil {
		return mapError(err)
	}

	if err = tx.Commit(); err != nil {
		return fmt.Errorf("commit create user: %w", err)
	}
	return nil
}

// FindByLogin returns a user by login.
func (r *UserRepository) FindByLogin(ctx context.Context, login string) (domain.User, error) {
	if err := ensureDB(r.db); err != nil {
		return domain.User{}, err
	}
	if login == "" {
		return domain.User{}, fmt.Errorf("%w: login is required", domain.ErrValidation)
	}

	row := r.db.QueryRowContext(ctx, selectUserSQL+` WHERE login = $1`, login)
	user, err := scanUser(row)
	if err != nil {
		return domain.User{}, mapError(err)
	}
	return user, nil
}

// FindByID returns a user by ID.
func (r *UserRepository) FindByID(ctx context.Context, id string) (domain.User, error) {
	if err := ensureDB(r.db); err != nil {
		return domain.User{}, err
	}
	if id == "" {
		return domain.User{}, fmt.Errorf("%w: user id is required", domain.ErrValidation)
	}

	row := r.db.QueryRowContext(ctx, selectUserSQL+` WHERE id = $1`, id)
	user, err := scanUser(row)
	if err != nil {
		return domain.User{}, mapError(err)
	}
	return user, nil
}

// RefreshTokenRepository persists refresh tokens in PostgreSQL.
type RefreshTokenRepository struct {
	db *sql.DB
}

// NewRefreshTokenRepository creates a refresh token repository.
func NewRefreshTokenRepository(db *sql.DB) *RefreshTokenRepository {
	return &RefreshTokenRepository{db: db}
}

// Create inserts a refresh token.
func (r *RefreshTokenRepository) Create(ctx context.Context, token domain.RefreshToken) error {
	if err := ensureDB(r.db); err != nil {
		return err
	}
	if err := token.Validate(); err != nil {
		return err
	}
	if token.CreatedAt.IsZero() {
		token.CreatedAt = time.Now().UTC()
	}

	_, err := r.db.ExecContext(
		ctx,
		`INSERT INTO refresh_tokens (id, user_id, token_hash, client_id, expires_at, revoked_at, created_at)
VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		token.ID,
		token.UserID,
		token.TokenHash,
		token.ClientID,
		token.ExpiresAt,
		token.RevokedAt,
		token.CreatedAt,
	)
	return mapError(err)
}

// FindByHash returns a refresh token by token hash.
func (r *RefreshTokenRepository) FindByHash(ctx context.Context, hash []byte) (domain.RefreshToken, error) {
	if err := ensureDB(r.db); err != nil {
		return domain.RefreshToken{}, err
	}
	if len(hash) == 0 {
		return domain.RefreshToken{}, fmt.Errorf("%w: token hash is required", domain.ErrValidation)
	}

	row := r.db.QueryRowContext(ctx, selectRefreshTokenSQL+` WHERE token_hash = $1`, hash)
	token, err := scanRefreshToken(row)
	if err != nil {
		return domain.RefreshToken{}, mapError(err)
	}
	return token, nil
}

// Revoke marks a refresh token as revoked.
func (r *RefreshTokenRepository) Revoke(ctx context.Context, id string, revokedAt time.Time) error {
	if err := ensureDB(r.db); err != nil {
		return err
	}
	if id == "" {
		return fmt.Errorf("%w: refresh token id is required", domain.ErrValidation)
	}
	if revokedAt.IsZero() {
		return fmt.Errorf("%w: revoked at is required", domain.ErrValidation)
	}

	result, err := r.db.ExecContext(
		ctx,
		`UPDATE refresh_tokens SET revoked_at = $2 WHERE id = $1 AND revoked_at IS NULL`,
		id,
		revokedAt,
	)
	if err != nil {
		return mapError(err)
	}

	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("read revoked rows affected: %w", err)
	}
	if affected == 0 {
		return domain.ErrNotFound
	}
	return nil
}

// VaultItemRepository persists encrypted vault items in PostgreSQL.
type VaultItemRepository struct {
	db *sql.DB
}

// NewVaultItemRepository creates a vault item repository.
func NewVaultItemRepository(db *sql.DB) *VaultItemRepository {
	return &VaultItemRepository{db: db}
}

// Upsert creates or replaces an encrypted vault item.
func (r *VaultItemRepository) Upsert(ctx context.Context, item domain.VaultItem) error {
	if err := ensureDB(r.db); err != nil {
		return err
	}
	if err := item.Validate(); err != nil {
		return err
	}

	now := time.Now().UTC()
	if item.CreatedAt.IsZero() {
		item.CreatedAt = now
	}
	if item.UpdatedAt.IsZero() {
		item.UpdatedAt = now
	}

	_, err := r.db.ExecContext(
		ctx,
		upsertVaultItemSQL,
		item.ID,
		item.UserID,
		item.ServerRevision,
		item.EncryptedPayload,
		item.PayloadNonce,
		item.PayloadVersion,
		item.DeletedAt,
		item.CreatedAt,
		item.UpdatedAt,
	)
	return mapError(err)
}

// ApplyMutation atomically applies one encrypted sync mutation and advances the user's revision.
func (r *VaultItemRepository) ApplyMutation(ctx context.Context, userID string, mutation syncsvc.Mutation, now time.Time) (domain.VaultItem, *syncsvc.Conflict, error) {
	if err := ensureDB(r.db); err != nil {
		return domain.VaultItem{}, nil, err
	}
	if userID == "" {
		return domain.VaultItem{}, nil, fmt.Errorf("%w: user id is required", domain.ErrValidation)
	}
	if err := mutation.Validate(); err != nil {
		return domain.VaultItem{}, nil, err
	}
	if now.IsZero() {
		now = time.Now()
	}
	now = now.UTC()

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return domain.VaultItem{}, nil, fmt.Errorf("begin sync mutation: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	row := tx.QueryRowContext(ctx, selectVaultItemSQL+` WHERE user_id = $1 AND id = $2 FOR UPDATE`, userID, mutation.ID)
	current, err := scanVaultItem(row)
	switch {
	case err == nil:
		if current.ServerRevision != mutation.BaseRevision {
			remote := current.Clone()
			return domain.VaultItem{}, &syncsvc.Conflict{
				ID:             mutation.ID,
				BaseRevision:   mutation.BaseRevision,
				ServerRevision: current.ServerRevision,
				Reason:         "revision_mismatch",
				Remote:         &remote,
			}, nil
		}
	case errors.Is(err, sql.ErrNoRows):
		if mutation.BaseRevision != 0 {
			return domain.VaultItem{}, &syncsvc.Conflict{
				ID:           mutation.ID,
				BaseRevision: mutation.BaseRevision,
				Reason:       "missing_remote_item",
			}, nil
		}
	default:
		return domain.VaultItem{}, nil, mapError(err)
	}

	var revision int64
	if err = tx.QueryRowContext(
		ctx,
		`UPDATE user_sync_state
SET current_revision = current_revision + 1
WHERE user_id = $1
RETURNING current_revision`,
		userID,
	).Scan(&revision); err != nil {
		return domain.VaultItem{}, nil, mapError(err)
	}

	item := domain.VaultItem{
		ID:               mutation.ID,
		UserID:           userID,
		ServerRevision:   revision,
		EncryptedPayload: append([]byte(nil), mutation.EncryptedPayload...),
		PayloadNonce:     append([]byte(nil), mutation.PayloadNonce...),
		PayloadVersion:   mutation.PayloadVersion,
		DeletedAt:        cloneTimePtr(mutation.DeletedAt),
		CreatedAt:        now,
		UpdatedAt:        now,
	}
	if current.ID != "" {
		item.CreatedAt = current.CreatedAt
	}
	if item.DeletedAt != nil {
		item.UpdatedAt = item.DeletedAt.UTC()
	}
	if err = item.Validate(); err != nil {
		return domain.VaultItem{}, nil, err
	}

	if _, err = tx.ExecContext(
		ctx,
		upsertVaultItemSQL,
		item.ID,
		item.UserID,
		item.ServerRevision,
		item.EncryptedPayload,
		item.PayloadNonce,
		item.PayloadVersion,
		item.DeletedAt,
		item.CreatedAt,
		item.UpdatedAt,
	); err != nil {
		return domain.VaultItem{}, nil, mapError(err)
	}

	if err = tx.Commit(); err != nil {
		return domain.VaultItem{}, nil, fmt.Errorf("commit sync mutation: %w", err)
	}
	committed = true
	return item.Clone(), nil, nil
}

// Find returns one encrypted vault item.
func (r *VaultItemRepository) Find(ctx context.Context, userID, itemID string) (domain.VaultItem, error) {
	if err := ensureDB(r.db); err != nil {
		return domain.VaultItem{}, err
	}
	if userID == "" {
		return domain.VaultItem{}, fmt.Errorf("%w: user id is required", domain.ErrValidation)
	}
	if itemID == "" {
		return domain.VaultItem{}, fmt.Errorf("%w: vault item id is required", domain.ErrValidation)
	}

	row := r.db.QueryRowContext(ctx, selectVaultItemSQL+` WHERE user_id = $1 AND id = $2`, userID, itemID)
	item, err := scanVaultItem(row)
	if err != nil {
		return domain.VaultItem{}, mapError(err)
	}
	return item, nil
}

// ListChanged returns items changed after sinceRevision.
func (r *VaultItemRepository) ListChanged(ctx context.Context, userID string, sinceRevision int64, limit int) ([]domain.VaultItem, error) {
	if err := ensureDB(r.db); err != nil {
		return nil, err
	}
	if userID == "" {
		return nil, fmt.Errorf("%w: user id is required", domain.ErrValidation)
	}
	if sinceRevision < 0 {
		return nil, fmt.Errorf("%w: since revision must be non-negative", domain.ErrValidation)
	}
	if limit <= 0 {
		limit = defaultListChangedLimit
	}

	rows, err := r.db.QueryContext(
		ctx,
		selectVaultItemSQL+` WHERE user_id = $1 AND server_revision > $2 ORDER BY server_revision ASC LIMIT $3`,
		userID,
		sinceRevision,
		limit,
	)
	if err != nil {
		return nil, mapError(err)
	}
	defer func() {
		_ = rows.Close()
	}()

	items := make([]domain.VaultItem, 0)
	for rows.Next() {
		item, err := scanVaultItem(rows)
		if err != nil {
			return nil, mapError(err)
		}
		items = append(items, item)
	}
	if err = rows.Err(); err != nil {
		return nil, mapError(err)
	}

	return items, nil
}

// SoftDelete marks an existing vault item as deleted and returns the tombstone.
func (r *VaultItemRepository) SoftDelete(ctx context.Context, userID, itemID string, revision int64, deletedAt time.Time) (domain.VaultItem, error) {
	if err := ensureDB(r.db); err != nil {
		return domain.VaultItem{}, err
	}
	if userID == "" {
		return domain.VaultItem{}, fmt.Errorf("%w: user id is required", domain.ErrValidation)
	}
	if itemID == "" {
		return domain.VaultItem{}, fmt.Errorf("%w: vault item id is required", domain.ErrValidation)
	}
	if revision < 0 {
		return domain.VaultItem{}, fmt.Errorf("%w: revision must be non-negative", domain.ErrValidation)
	}
	if deletedAt.IsZero() {
		return domain.VaultItem{}, fmt.Errorf("%w: deleted at is required", domain.ErrValidation)
	}

	row := r.db.QueryRowContext(
		ctx,
		`UPDATE vault_items
SET server_revision = $3, deleted_at = $4, updated_at = $4
WHERE user_id = $1 AND id = $2
RETURNING id, user_id, server_revision, encrypted_payload, payload_nonce, payload_version, deleted_at, created_at, updated_at`,
		userID,
		itemID,
		revision,
		deletedAt,
	)
	item, err := scanVaultItem(row)
	if err != nil {
		return domain.VaultItem{}, mapError(err)
	}
	return item, nil
}

// SyncStateRepository persists per-user sync revisions in PostgreSQL.
type SyncStateRepository struct {
	db *sql.DB
}

// NewSyncStateRepository creates a sync state repository.
func NewSyncStateRepository(db *sql.DB) *SyncStateRepository {
	return &SyncStateRepository{db: db}
}

// Get returns the current sync state for a user.
func (r *SyncStateRepository) Get(ctx context.Context, userID string) (domain.SyncState, error) {
	if err := ensureDB(r.db); err != nil {
		return domain.SyncState{}, err
	}
	if userID == "" {
		return domain.SyncState{}, fmt.Errorf("%w: user id is required", domain.ErrValidation)
	}

	var state domain.SyncState
	err := r.db.QueryRowContext(
		ctx,
		`SELECT user_id, current_revision FROM user_sync_state WHERE user_id = $1`,
		userID,
	).Scan(&state.UserID, &state.CurrentRevision)
	if err != nil {
		return domain.SyncState{}, mapError(err)
	}
	return state, nil
}

// Set stores an exact current revision for a user.
func (r *SyncStateRepository) Set(ctx context.Context, state domain.SyncState) error {
	if err := ensureDB(r.db); err != nil {
		return err
	}
	if err := state.Validate(); err != nil {
		return err
	}

	_, err := r.db.ExecContext(
		ctx,
		`INSERT INTO user_sync_state (user_id, current_revision) VALUES ($1, $2)
ON CONFLICT (user_id) DO UPDATE SET current_revision = EXCLUDED.current_revision`,
		state.UserID,
		state.CurrentRevision,
	)
	return mapError(err)
}

// Increment increments and returns the current revision for a user.
func (r *SyncStateRepository) Increment(ctx context.Context, userID string) (int64, error) {
	if err := ensureDB(r.db); err != nil {
		return 0, err
	}
	if userID == "" {
		return 0, fmt.Errorf("%w: user id is required", domain.ErrValidation)
	}

	var revision int64
	err := r.db.QueryRowContext(
		ctx,
		`UPDATE user_sync_state
SET current_revision = current_revision + 1
WHERE user_id = $1
RETURNING current_revision`,
		userID,
	).Scan(&revision)
	if err != nil {
		return 0, mapError(err)
	}
	return revision, nil
}

type scanner interface {
	Scan(dest ...any) error
}

const selectUserSQL = `SELECT id, login, auth_salt, vault_salt, auth_secret_hash, kdf_params, created_at, updated_at FROM users`
const selectRefreshTokenSQL = `SELECT id, user_id, token_hash, client_id, expires_at, revoked_at, created_at FROM refresh_tokens`
const selectVaultItemSQL = `SELECT id, user_id, server_revision, encrypted_payload, payload_nonce, payload_version, deleted_at, created_at, updated_at FROM vault_items`
const upsertVaultItemSQL = `INSERT INTO vault_items (id, user_id, server_revision, encrypted_payload, payload_nonce, payload_version, deleted_at, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
ON CONFLICT (user_id, id) DO UPDATE SET
    server_revision = EXCLUDED.server_revision,
    encrypted_payload = EXCLUDED.encrypted_payload,
    payload_nonce = EXCLUDED.payload_nonce,
    payload_version = EXCLUDED.payload_version,
    deleted_at = EXCLUDED.deleted_at,
    updated_at = EXCLUDED.updated_at`

func scanUser(row scanner) (domain.User, error) {
	var (
		user      domain.User
		kdfParams []byte
	)
	if err := row.Scan(
		&user.ID,
		&user.Login,
		&user.AuthSalt,
		&user.VaultSalt,
		&user.AuthSecretHash,
		&kdfParams,
		&user.CreatedAt,
		&user.UpdatedAt,
	); err != nil {
		return domain.User{}, err
	}
	user.KDFParams = kdfParams
	return user, nil
}

func scanRefreshToken(row scanner) (domain.RefreshToken, error) {
	var (
		token     domain.RefreshToken
		revokedAt sql.NullTime
	)
	if err := row.Scan(
		&token.ID,
		&token.UserID,
		&token.TokenHash,
		&token.ClientID,
		&token.ExpiresAt,
		&revokedAt,
		&token.CreatedAt,
	); err != nil {
		return domain.RefreshToken{}, err
	}
	if revokedAt.Valid {
		token.RevokedAt = &revokedAt.Time
	}
	return token, nil
}

func scanVaultItem(row scanner) (domain.VaultItem, error) {
	var (
		item      domain.VaultItem
		deletedAt sql.NullTime
	)
	if err := row.Scan(
		&item.ID,
		&item.UserID,
		&item.ServerRevision,
		&item.EncryptedPayload,
		&item.PayloadNonce,
		&item.PayloadVersion,
		&deletedAt,
		&item.CreatedAt,
		&item.UpdatedAt,
	); err != nil {
		return domain.VaultItem{}, err
	}
	if deletedAt.Valid {
		item.DeletedAt = &deletedAt.Time
	}
	return item, nil
}

func ensureDB(db *sql.DB) error {
	if db == nil {
		return errors.New("postgres repository: db is nil")
	}
	return nil
}

func cloneTimePtr(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	cloned := value.UTC()
	return &cloned
}
