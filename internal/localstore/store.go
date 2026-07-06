package localstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

const schemaSQL = `
CREATE TABLE IF NOT EXISTS profiles (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    server_url TEXT NOT NULL,
    user_id TEXT NOT NULL,
    login TEXT NOT NULL,
    client_id TEXT NOT NULL,
    auth_salt BLOB NOT NULL,
    vault_salt BLOB NOT NULL,
    kdf_params BLOB NOT NULL,
    last_revision INTEGER NOT NULL DEFAULT 0,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    access_token TEXT NOT NULL,
    access_expires_at TEXT NOT NULL,
    refresh_token TEXT NOT NULL,
    refresh_expires_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS items (
    id TEXT PRIMARY KEY,
    server_revision INTEGER NOT NULL DEFAULT 0,
    encrypted_payload BLOB NOT NULL,
    payload_nonce BLOB NOT NULL,
    payload_version INTEGER NOT NULL DEFAULT 1,
    deleted_at TEXT,
    dirty_state TEXT NOT NULL DEFAULT 'clean',
    updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS items_dirty_state_idx ON items(dirty_state);

CREATE TABLE IF NOT EXISTS item_conflicts (
    item_id TEXT PRIMARY KEY,
    reason TEXT NOT NULL,
    local_revision INTEGER NOT NULL DEFAULT 0,
    remote_revision INTEGER,
    remote_encrypted_payload BLOB,
    remote_payload_nonce BLOB,
    remote_payload_version INTEGER,
    remote_deleted_at TEXT,
    remote_updated_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
`

var (
	// ErrNotFound reports that a local profile or session does not exist.
	ErrNotFound = errors.New("not found")
)

const (
	// DirtyStateClean means the item matches the last known server state.
	DirtyStateClean = "clean"
	// DirtyStateUpsert means the item must be created or updated on the server.
	DirtyStateUpsert = "upsert"
	// DirtyStateDelete means the local tombstone must be pushed to the server.
	DirtyStateDelete = "delete"
	// DirtyStateConflict means local and remote mutations need explicit resolution.
	DirtyStateConflict = "conflict"
)

// Profile describes the current local client profile.
type Profile struct {
	ServerURL    string
	UserID       string
	Login        string
	ClientID     string
	AuthSalt     []byte
	VaultSalt    []byte
	KDFParams    []byte
	LastRevision int64
	UpdatedAt    time.Time
}

// Session describes locally cached authentication tokens.
type Session struct {
	AccessToken      string
	AccessExpiresAt  time.Time
	RefreshToken     string
	RefreshExpiresAt time.Time
	UpdatedAt        time.Time
}

// Item describes an encrypted vault item cached by the CLI client.
type Item struct {
	ID               string
	ServerRevision   int64
	EncryptedPayload []byte
	PayloadNonce     []byte
	PayloadVersion   int16
	DeletedAt        *time.Time
	DirtyState       string
	UpdatedAt        time.Time
}

// Conflict stores a remote item candidate for a local synchronization conflict.
type Conflict struct {
	ItemID        string
	Reason        string
	LocalRevision int64
	RemoteItem    *Item
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// Status summarizes the local store for CLI display.
type Status struct {
	HasProfile    bool
	HasSession    bool
	ServerURL     string
	UserID        string
	Login         string
	ClientID      string
	LastRevision  int64
	ItemCount     int
	DirtyCount    int
	ConflictCount int
}

// Store is a SQLite-backed local client store.
type Store struct {
	db *sql.DB
}

// Open opens or creates a local store at path.
func Open(path string) (*Store, error) {
	if path == "" {
		return nil, errors.New("local store path is required")
	}

	cleanPath := filepath.Clean(path)
	if err := os.MkdirAll(filepath.Dir(cleanPath), 0o700); err != nil {
		return nil, fmt.Errorf("create local store directory: %w", err)
	}

	db, err := sql.Open("sqlite", cleanPath)
	if err != nil {
		return nil, fmt.Errorf("open local store: %w", err)
	}
	if _, err = db.Exec(schemaSQL); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("initialize local store schema: %w", err)
	}
	if err = ensureItemPayloadVersionColumn(db); err != nil {
		_ = db.Close()
		return nil, err
	}
	_ = os.Chmod(cleanPath, 0o600)

	return &Store{db: db}, nil
}

// Close releases local store resources.
func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

// SaveProfile stores the current local profile.
func (s *Store) SaveProfile(ctx context.Context, profile Profile) error {
	if err := profile.Validate(); err != nil {
		return err
	}
	if profile.UpdatedAt.IsZero() {
		profile.UpdatedAt = time.Now().UTC()
	}

	_, err := s.db.ExecContext(
		ctx,
		`INSERT INTO profiles (id, server_url, user_id, login, client_id, auth_salt, vault_salt, kdf_params, last_revision, updated_at)
VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(id) DO UPDATE SET
    server_url = excluded.server_url,
    user_id = excluded.user_id,
    login = excluded.login,
    client_id = excluded.client_id,
    auth_salt = excluded.auth_salt,
    vault_salt = excluded.vault_salt,
    kdf_params = excluded.kdf_params,
    last_revision = excluded.last_revision,
    updated_at = excluded.updated_at`,
		profile.ServerURL,
		profile.UserID,
		profile.Login,
		profile.ClientID,
		profile.AuthSalt,
		profile.VaultSalt,
		profile.KDFParams,
		profile.LastRevision,
		formatTime(profile.UpdatedAt),
	)
	if err != nil {
		return fmt.Errorf("save profile: %w", err)
	}
	return nil
}

// Profile returns the current local profile.
func (s *Store) Profile(ctx context.Context) (Profile, error) {
	row := s.db.QueryRowContext(
		ctx,
		`SELECT server_url, user_id, login, client_id, auth_salt, vault_salt, kdf_params, last_revision, updated_at FROM profiles WHERE id = 1`,
	)

	var (
		profile   Profile
		updatedAt string
	)
	err := row.Scan(
		&profile.ServerURL,
		&profile.UserID,
		&profile.Login,
		&profile.ClientID,
		&profile.AuthSalt,
		&profile.VaultSalt,
		&profile.KDFParams,
		&profile.LastRevision,
		&updatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return Profile{}, ErrNotFound
	}
	if err != nil {
		return Profile{}, fmt.Errorf("load profile: %w", err)
	}
	profile.UpdatedAt, err = parseTime(updatedAt)
	if err != nil {
		return Profile{}, err
	}
	return profile, nil
}

// SaveSession stores the current authentication session.
func (s *Store) SaveSession(ctx context.Context, session Session) error {
	if err := session.Validate(); err != nil {
		return err
	}
	if session.UpdatedAt.IsZero() {
		session.UpdatedAt = time.Now().UTC()
	}

	_, err := s.db.ExecContext(
		ctx,
		`INSERT INTO sessions (id, access_token, access_expires_at, refresh_token, refresh_expires_at, updated_at)
VALUES (1, ?, ?, ?, ?, ?)
ON CONFLICT(id) DO UPDATE SET
    access_token = excluded.access_token,
    access_expires_at = excluded.access_expires_at,
    refresh_token = excluded.refresh_token,
    refresh_expires_at = excluded.refresh_expires_at,
    updated_at = excluded.updated_at`,
		session.AccessToken,
		formatTime(session.AccessExpiresAt),
		session.RefreshToken,
		formatTime(session.RefreshExpiresAt),
		formatTime(session.UpdatedAt),
	)
	if err != nil {
		return fmt.Errorf("save session: %w", err)
	}
	return nil
}

// Session returns the current authentication session.
func (s *Store) Session(ctx context.Context) (Session, error) {
	row := s.db.QueryRowContext(
		ctx,
		`SELECT access_token, access_expires_at, refresh_token, refresh_expires_at, updated_at FROM sessions WHERE id = 1`,
	)

	var (
		session          Session
		accessExpiresAt  string
		refreshExpiresAt string
		updatedAt        string
	)
	err := row.Scan(
		&session.AccessToken,
		&accessExpiresAt,
		&session.RefreshToken,
		&refreshExpiresAt,
		&updatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return Session{}, ErrNotFound
	}
	if err != nil {
		return Session{}, fmt.Errorf("load session: %w", err)
	}
	var parseErr error
	session.AccessExpiresAt, parseErr = parseTime(accessExpiresAt)
	if parseErr != nil {
		return Session{}, parseErr
	}
	session.RefreshExpiresAt, parseErr = parseTime(refreshExpiresAt)
	if parseErr != nil {
		return Session{}, parseErr
	}
	session.UpdatedAt, parseErr = parseTime(updatedAt)
	if parseErr != nil {
		return Session{}, parseErr
	}
	return session, nil
}

// ClearSession removes the current authentication session.
func (s *Store) ClearSession(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE id = 1`); err != nil {
		return fmt.Errorf("clear session: %w", err)
	}
	return nil
}

// SaveItem stores or updates an encrypted local item.
func (s *Store) SaveItem(ctx context.Context, item Item) error {
	return s.saveItem(ctx, s.db, item)
}

func (s *Store) saveItem(ctx context.Context, exec sqlExecutor, item Item) error {
	if item.DirtyState == "" {
		item.DirtyState = DirtyStateClean
	}
	if item.PayloadVersion == 0 {
		item.PayloadVersion = 1
	}
	if item.UpdatedAt.IsZero() {
		item.UpdatedAt = time.Now().UTC()
	}
	if err := item.Validate(); err != nil {
		return err
	}

	var deletedAt sql.NullString
	if item.DeletedAt != nil {
		deletedAt.Valid = true
		deletedAt.String = formatTime(*item.DeletedAt)
	}

	_, err := exec.ExecContext(
		ctx,
		`INSERT INTO items (id, server_revision, encrypted_payload, payload_nonce, payload_version, deleted_at, dirty_state, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(id) DO UPDATE SET
    server_revision = excluded.server_revision,
    encrypted_payload = excluded.encrypted_payload,
    payload_nonce = excluded.payload_nonce,
    payload_version = excluded.payload_version,
    deleted_at = excluded.deleted_at,
    dirty_state = excluded.dirty_state,
    updated_at = excluded.updated_at`,
		item.ID,
		item.ServerRevision,
		item.EncryptedPayload,
		item.PayloadNonce,
		item.PayloadVersion,
		deletedAt,
		item.DirtyState,
		formatTime(item.UpdatedAt),
	)
	if err != nil {
		return fmt.Errorf("save item: %w", err)
	}
	return nil
}

// SaveItemAndClearConflict stores an item and clears its conflict record in one transaction.
func (s *Store) SaveItemAndClearConflict(ctx context.Context, item Item) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin save item and clear conflict: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	if err = s.saveItem(ctx, tx, item); err != nil {
		return err
	}
	if err = s.clearConflict(ctx, tx, item.ID); err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return fmt.Errorf("commit save item and clear conflict: %w", err)
	}
	committed = true
	return nil
}

// SaveItemAndConflict stores an item and its conflict record in one transaction.
func (s *Store) SaveItemAndConflict(ctx context.Context, item Item, conflict Conflict) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin save item and conflict: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	if err = s.saveItem(ctx, tx, item); err != nil {
		return err
	}
	if err = s.saveConflict(ctx, tx, conflict); err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return fmt.Errorf("commit save item and conflict: %w", err)
	}
	committed = true
	return nil
}

// Item returns one encrypted local item by id.
func (s *Store) Item(ctx context.Context, id string) (Item, error) {
	if strings.TrimSpace(id) == "" {
		return Item{}, errors.New("item id is required")
	}

	row := s.db.QueryRowContext(
		ctx,
		`SELECT id, server_revision, encrypted_payload, payload_nonce, payload_version, deleted_at, dirty_state, updated_at
FROM items WHERE id = ?`,
		id,
	)

	item, err := scanItem(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Item{}, ErrNotFound
	}
	if err != nil {
		return Item{}, fmt.Errorf("load item: %w", err)
	}
	return item, nil
}

// ListItems returns encrypted local items ordered by update time.
func (s *Store) ListItems(ctx context.Context, includeDeleted bool) ([]Item, error) {
	query := `SELECT id, server_revision, encrypted_payload, payload_nonce, payload_version, deleted_at, dirty_state, updated_at FROM items`
	if !includeDeleted {
		query += ` WHERE deleted_at IS NULL`
	}
	query += ` ORDER BY updated_at DESC, id`

	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("list items: %w", err)
	}
	defer func() {
		_ = rows.Close()
	}()

	var items []Item
	for rows.Next() {
		item, scanErr := scanItem(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		items = append(items, item)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("list items: %w", err)
	}
	return items, nil
}

// DeleteItem marks a local item as deleted and dirty for synchronization.
func (s *Store) DeleteItem(ctx context.Context, id string, deletedAt time.Time) error {
	if strings.TrimSpace(id) == "" {
		return errors.New("item id is required")
	}
	if deletedAt.IsZero() {
		deletedAt = time.Now().UTC()
	}

	result, err := s.db.ExecContext(
		ctx,
		`UPDATE items SET deleted_at = ?, dirty_state = ?, updated_at = ? WHERE id = ?`,
		formatTime(deletedAt),
		DirtyStateDelete,
		formatTime(deletedAt),
		id,
	)
	if err != nil {
		return fmt.Errorf("delete item: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("delete item: %w", err)
	}
	if affected == 0 {
		return ErrNotFound
	}
	return nil
}

// SaveConflict stores a synchronization conflict for later resolution.
func (s *Store) SaveConflict(ctx context.Context, conflict Conflict) error {
	return s.saveConflict(ctx, s.db, conflict)
}

func (s *Store) saveConflict(ctx context.Context, exec sqlExecutor, conflict Conflict) error {
	if conflict.CreatedAt.IsZero() {
		conflict.CreatedAt = time.Now().UTC()
	}
	if conflict.UpdatedAt.IsZero() {
		conflict.UpdatedAt = conflict.CreatedAt
	}
	if err := conflict.Validate(); err != nil {
		return err
	}

	var (
		remoteRevision         sql.NullInt64
		remoteEncryptedPayload []byte
		remotePayloadNonce     []byte
		remotePayloadVersion   sql.NullInt64
		remoteDeletedAt        sql.NullString
		remoteUpdatedAt        sql.NullString
	)
	if conflict.RemoteItem != nil {
		remote := conflict.RemoteItem
		remoteRevision.Valid = true
		remoteRevision.Int64 = remote.ServerRevision
		remoteEncryptedPayload = remote.EncryptedPayload
		remotePayloadNonce = remote.PayloadNonce
		remotePayloadVersion.Valid = true
		remotePayloadVersion.Int64 = int64(remote.PayloadVersion)
		remoteUpdatedAt.Valid = true
		remoteUpdatedAt.String = formatTime(remote.UpdatedAt)
		if remote.DeletedAt != nil {
			remoteDeletedAt.Valid = true
			remoteDeletedAt.String = formatTime(*remote.DeletedAt)
		}
	}

	_, err := exec.ExecContext(
		ctx,
		`INSERT INTO item_conflicts (
    item_id, reason, local_revision, remote_revision, remote_encrypted_payload,
    remote_payload_nonce, remote_payload_version, remote_deleted_at, remote_updated_at,
    created_at, updated_at
)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(item_id) DO UPDATE SET
    reason = excluded.reason,
    local_revision = excluded.local_revision,
    remote_revision = excluded.remote_revision,
    remote_encrypted_payload = excluded.remote_encrypted_payload,
    remote_payload_nonce = excluded.remote_payload_nonce,
    remote_payload_version = excluded.remote_payload_version,
    remote_deleted_at = excluded.remote_deleted_at,
    remote_updated_at = excluded.remote_updated_at,
    updated_at = excluded.updated_at`,
		conflict.ItemID,
		conflict.Reason,
		conflict.LocalRevision,
		remoteRevision,
		remoteEncryptedPayload,
		remotePayloadNonce,
		remotePayloadVersion,
		remoteDeletedAt,
		remoteUpdatedAt,
		formatTime(conflict.CreatedAt),
		formatTime(conflict.UpdatedAt),
	)
	if err != nil {
		return fmt.Errorf("save conflict: %w", err)
	}
	return nil
}

// Conflict returns one stored synchronization conflict.
func (s *Store) Conflict(ctx context.Context, itemID string) (Conflict, error) {
	if strings.TrimSpace(itemID) == "" {
		return Conflict{}, errors.New("item id is required")
	}

	row := s.db.QueryRowContext(
		ctx,
		`SELECT item_id, reason, local_revision, remote_revision, remote_encrypted_payload,
    remote_payload_nonce, remote_payload_version, remote_deleted_at, remote_updated_at,
    created_at, updated_at
FROM item_conflicts WHERE item_id = ?`,
		itemID,
	)
	conflict, err := scanConflict(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Conflict{}, ErrNotFound
	}
	if err != nil {
		return Conflict{}, fmt.Errorf("load conflict: %w", err)
	}
	return conflict, nil
}

// ListConflicts returns all stored synchronization conflicts.
func (s *Store) ListConflicts(ctx context.Context) ([]Conflict, error) {
	rows, err := s.db.QueryContext(
		ctx,
		`SELECT item_id, reason, local_revision, remote_revision, remote_encrypted_payload,
    remote_payload_nonce, remote_payload_version, remote_deleted_at, remote_updated_at,
    created_at, updated_at
FROM item_conflicts ORDER BY updated_at DESC, item_id`,
	)
	if err != nil {
		return nil, fmt.Errorf("list conflicts: %w", err)
	}
	defer func() {
		_ = rows.Close()
	}()

	conflicts := make([]Conflict, 0)
	for rows.Next() {
		conflict, scanErr := scanConflict(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		conflicts = append(conflicts, conflict)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("list conflicts: %w", err)
	}
	return conflicts, nil
}

// ClearConflict removes a stored synchronization conflict.
func (s *Store) ClearConflict(ctx context.Context, itemID string) error {
	return s.clearConflict(ctx, s.db, itemID)
}

func (s *Store) clearConflict(ctx context.Context, exec sqlExecutor, itemID string) error {
	if strings.TrimSpace(itemID) == "" {
		return errors.New("item id is required")
	}
	if _, err := exec.ExecContext(ctx, `DELETE FROM item_conflicts WHERE item_id = ?`, itemID); err != nil {
		return fmt.Errorf("clear conflict: %w", err)
	}
	return nil
}

// Status returns a summary of local profile, session, and item state.
func (s *Store) Status(ctx context.Context) (Status, error) {
	var status Status

	profile, err := s.Profile(ctx)
	switch {
	case err == nil:
		status.HasProfile = true
		status.ServerURL = profile.ServerURL
		status.UserID = profile.UserID
		status.Login = profile.Login
		status.ClientID = profile.ClientID
		status.LastRevision = profile.LastRevision
	case errors.Is(err, ErrNotFound):
	default:
		return Status{}, err
	}

	_, err = s.Session(ctx)
	switch {
	case err == nil:
		status.HasSession = true
	case errors.Is(err, ErrNotFound):
	default:
		return Status{}, err
	}

	if err = s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM items WHERE deleted_at IS NULL`).Scan(&status.ItemCount); err != nil {
		return Status{}, fmt.Errorf("count local items: %w", err)
	}
	if err = s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM items WHERE dirty_state <> 'clean'`).Scan(&status.DirtyCount); err != nil {
		return Status{}, fmt.Errorf("count dirty local items: %w", err)
	}
	if err = s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM item_conflicts`).Scan(&status.ConflictCount); err != nil {
		return Status{}, fmt.Errorf("count local conflicts: %w", err)
	}

	return status, nil
}

// Validate checks profile data before persistence.
func (p Profile) Validate() error {
	if p.ServerURL == "" {
		return errors.New("server url is required")
	}
	if p.UserID == "" {
		return errors.New("user id is required")
	}
	if p.Login == "" {
		return errors.New("login is required")
	}
	if p.ClientID == "" {
		return errors.New("client id is required")
	}
	if len(p.AuthSalt) == 0 {
		return errors.New("auth salt is required")
	}
	if len(p.VaultSalt) == 0 {
		return errors.New("vault salt is required")
	}
	if len(p.KDFParams) == 0 {
		return errors.New("kdf params are required")
	}
	if p.LastRevision < 0 {
		return errors.New("last revision must be non-negative")
	}
	return nil
}

// Validate checks session data before persistence.
func (s Session) Validate() error {
	if s.AccessToken == "" {
		return errors.New("access token is required")
	}
	if s.AccessExpiresAt.IsZero() {
		return errors.New("access token expiration is required")
	}
	if s.RefreshToken == "" {
		return errors.New("refresh token is required")
	}
	if s.RefreshExpiresAt.IsZero() {
		return errors.New("refresh token expiration is required")
	}
	return nil
}

// Validate checks local item data before persistence.
func (i Item) Validate() error {
	if strings.TrimSpace(i.ID) == "" {
		return errors.New("item id is required")
	}
	if i.ServerRevision < 0 {
		return errors.New("server revision must be non-negative")
	}
	if len(i.EncryptedPayload) == 0 {
		return errors.New("encrypted payload is required")
	}
	if len(i.PayloadNonce) == 0 {
		return errors.New("payload nonce is required")
	}
	if i.PayloadVersion <= 0 {
		return errors.New("payload version must be positive")
	}
	if err := validateDirtyState(i.DirtyState); err != nil {
		return err
	}
	return nil
}

// Validate checks conflict data before persistence.
func (c Conflict) Validate() error {
	if strings.TrimSpace(c.ItemID) == "" {
		return errors.New("conflict item id is required")
	}
	if strings.TrimSpace(c.Reason) == "" {
		return errors.New("conflict reason is required")
	}
	if c.LocalRevision < 0 {
		return errors.New("local revision must be non-negative")
	}
	if c.RemoteItem != nil {
		remote := c.RemoteItem.Clone()
		if remote.ID == "" {
			remote.ID = c.ItemID
		}
		if remote.ID != c.ItemID {
			return errors.New("remote item id must match conflict item id")
		}
		if remote.DirtyState == "" {
			remote.DirtyState = DirtyStateClean
		}
		if err := remote.Validate(); err != nil {
			return err
		}
	}
	return nil
}

// Clone returns a deep copy of the item.
func (i Item) Clone() Item {
	i.EncryptedPayload = cloneBytes(i.EncryptedPayload)
	i.PayloadNonce = cloneBytes(i.PayloadNonce)
	if i.DeletedAt != nil {
		deletedAt := *i.DeletedAt
		i.DeletedAt = &deletedAt
	}
	return i
}

// Clone returns a deep copy of the conflict.
func (c Conflict) Clone() Conflict {
	if c.RemoteItem != nil {
		remote := c.RemoteItem.Clone()
		c.RemoteItem = &remote
	}
	return c
}

func ensureItemPayloadVersionColumn(db *sql.DB) error {
	rows, err := db.Query(`PRAGMA table_info(items)`)
	if err != nil {
		return fmt.Errorf("inspect local item schema: %w", err)
	}
	defer func() {
		_ = rows.Close()
	}()

	for rows.Next() {
		var (
			cid          int
			name         string
			columnType   string
			notNull      int
			defaultValue sql.NullString
			primaryKey   int
		)
		if err = rows.Scan(&cid, &name, &columnType, &notNull, &defaultValue, &primaryKey); err != nil {
			return fmt.Errorf("inspect local item schema: %w", err)
		}
		if name == "payload_version" {
			return nil
		}
	}
	if err = rows.Err(); err != nil {
		return fmt.Errorf("inspect local item schema: %w", err)
	}

	if _, err = db.Exec(`ALTER TABLE items ADD COLUMN payload_version INTEGER NOT NULL DEFAULT 1`); err != nil {
		return fmt.Errorf("migrate local item schema: %w", err)
	}
	return nil
}

type itemScanner interface {
	Scan(dest ...any) error
}

type sqlExecutor interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

func scanItem(scanner itemScanner) (Item, error) {
	var (
		item           Item
		payloadVersion int
		deletedAt      sql.NullString
		updatedAt      string
	)
	if err := scanner.Scan(
		&item.ID,
		&item.ServerRevision,
		&item.EncryptedPayload,
		&item.PayloadNonce,
		&payloadVersion,
		&deletedAt,
		&item.DirtyState,
		&updatedAt,
	); err != nil {
		return Item{}, err
	}

	item.PayloadVersion = int16(payloadVersion)
	var err error
	if deletedAt.Valid {
		parsed, parseErr := parseTime(deletedAt.String)
		if parseErr != nil {
			return Item{}, parseErr
		}
		item.DeletedAt = &parsed
	}
	item.UpdatedAt, err = parseTime(updatedAt)
	if err != nil {
		return Item{}, err
	}
	return item.Clone(), nil
}

func scanConflict(scanner itemScanner) (Conflict, error) {
	var (
		conflict             Conflict
		remoteRevision       sql.NullInt64
		remotePayload        []byte
		remoteNonce          []byte
		remotePayloadVersion sql.NullInt64
		remoteDeletedAt      sql.NullString
		remoteUpdatedAt      sql.NullString
		createdAt            string
		updatedAt            string
	)
	if err := scanner.Scan(
		&conflict.ItemID,
		&conflict.Reason,
		&conflict.LocalRevision,
		&remoteRevision,
		&remotePayload,
		&remoteNonce,
		&remotePayloadVersion,
		&remoteDeletedAt,
		&remoteUpdatedAt,
		&createdAt,
		&updatedAt,
	); err != nil {
		return Conflict{}, err
	}

	if remoteRevision.Valid {
		remote := Item{
			ID:               conflict.ItemID,
			ServerRevision:   remoteRevision.Int64,
			EncryptedPayload: cloneBytes(remotePayload),
			PayloadNonce:     cloneBytes(remoteNonce),
			PayloadVersion:   int16(remotePayloadVersion.Int64),
			DirtyState:       DirtyStateClean,
		}
		if remoteDeletedAt.Valid {
			deletedAt, err := parseTime(remoteDeletedAt.String)
			if err != nil {
				return Conflict{}, err
			}
			remote.DeletedAt = &deletedAt
		}
		if remoteUpdatedAt.Valid {
			parsed, err := parseTime(remoteUpdatedAt.String)
			if err != nil {
				return Conflict{}, err
			}
			remote.UpdatedAt = parsed
		}
		conflict.RemoteItem = &remote
	}

	var err error
	conflict.CreatedAt, err = parseTime(createdAt)
	if err != nil {
		return Conflict{}, err
	}
	conflict.UpdatedAt, err = parseTime(updatedAt)
	if err != nil {
		return Conflict{}, err
	}
	return conflict.Clone(), nil
}

func validateDirtyState(state string) error {
	switch state {
	case DirtyStateClean, DirtyStateUpsert, DirtyStateDelete, DirtyStateConflict:
		return nil
	default:
		return fmt.Errorf("unsupported dirty state %q", state)
	}
}

func cloneBytes(in []byte) []byte {
	if len(in) == 0 {
		return nil
	}
	return append([]byte(nil), in...)
}

func formatTime(value time.Time) string {
	return value.UTC().Format(time.RFC3339Nano)
}

func parseTime(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return time.Time{}, fmt.Errorf("parse local store time: %w", err)
	}
	return parsed, nil
}
