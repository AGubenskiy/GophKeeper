package domain

import (
	"encoding/json"
	"fmt"
	"time"
)

// User describes an account known by the GophKeeper server.
type User struct {
	ID             string
	Login          string
	AuthSalt       []byte
	VaultSalt      []byte
	AuthSecretHash string
	KDFParams      json.RawMessage
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// Validate checks that the user can be persisted by the server.
func (u User) Validate() error {
	if err := requireString("user id", u.ID); err != nil {
		return err
	}
	if err := requireString("login", u.Login); err != nil {
		return err
	}
	if err := requireBytes("auth salt", u.AuthSalt); err != nil {
		return err
	}
	if err := requireBytes("vault salt", u.VaultSalt); err != nil {
		return err
	}
	if err := requireString("auth secret hash", u.AuthSecretHash); err != nil {
		return err
	}
	if len(u.KDFParams) == 0 {
		return fmt.Errorf("%w: kdf params are required", ErrValidation)
	}
	if !json.Valid(u.KDFParams) {
		return fmt.Errorf("%w: kdf params must be valid JSON", ErrValidation)
	}
	return nil
}

// Clone returns a deep copy of the user.
func (u User) Clone() User {
	u.AuthSalt = cloneBytes(u.AuthSalt)
	u.VaultSalt = cloneBytes(u.VaultSalt)
	u.KDFParams = cloneBytes(u.KDFParams)
	return u
}
