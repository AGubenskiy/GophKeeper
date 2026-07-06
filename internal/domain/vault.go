package domain

import (
	"fmt"
	"time"
)

// VaultItem describes an encrypted item stored by the server.
type VaultItem struct {
	ID               string
	UserID           string
	ServerRevision   int64
	EncryptedPayload []byte
	PayloadNonce     []byte
	PayloadVersion   int16
	DeletedAt        *time.Time
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

// Validate checks that the vault item can be persisted by the server.
func (i VaultItem) Validate() error {
	if err := requireString("vault item id", i.ID); err != nil {
		return err
	}
	if err := requireString("user id", i.UserID); err != nil {
		return err
	}
	if i.ServerRevision < 0 {
		return fmt.Errorf("%w: server revision must be non-negative", ErrValidation)
	}
	if err := requireBytes("encrypted payload", i.EncryptedPayload); err != nil {
		return err
	}
	if err := requireBytes("payload nonce", i.PayloadNonce); err != nil {
		return err
	}
	if i.PayloadVersion <= 0 {
		return fmt.Errorf("%w: payload version must be positive", ErrValidation)
	}
	return nil
}

// Clone returns a deep copy of the item.
func (i VaultItem) Clone() VaultItem {
	i.EncryptedPayload = cloneBytes(i.EncryptedPayload)
	i.PayloadNonce = cloneBytes(i.PayloadNonce)
	if i.DeletedAt != nil {
		deletedAt := *i.DeletedAt
		i.DeletedAt = &deletedAt
	}
	return i
}

// SyncState stores the latest server revision for a user.
type SyncState struct {
	UserID          string
	CurrentRevision int64
}

// Validate checks that the sync state can be persisted by the server.
func (s SyncState) Validate() error {
	if err := requireString("user id", s.UserID); err != nil {
		return err
	}
	if s.CurrentRevision < 0 {
		return fmt.Errorf("%w: current revision must be non-negative", ErrValidation)
	}
	return nil
}
