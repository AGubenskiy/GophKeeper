package domain

import "time"

// RefreshToken describes a revocable long-lived authentication token.
type RefreshToken struct {
	ID        string
	UserID    string
	TokenHash []byte
	ClientID  string
	ExpiresAt time.Time
	RevokedAt *time.Time
	CreatedAt time.Time
}

// Validate checks that the refresh token can be persisted by the server.
func (t RefreshToken) Validate() error {
	if err := requireString("refresh token id", t.ID); err != nil {
		return err
	}
	if err := requireString("user id", t.UserID); err != nil {
		return err
	}
	if err := requireBytes("token hash", t.TokenHash); err != nil {
		return err
	}
	if err := requireString("client id", t.ClientID); err != nil {
		return err
	}
	if err := requireTime("expires at", t.ExpiresAt); err != nil {
		return err
	}
	return nil
}

// Clone returns a deep copy of the token.
func (t RefreshToken) Clone() RefreshToken {
	t.TokenHash = cloneBytes(t.TokenHash)
	if t.RevokedAt != nil {
		revokedAt := *t.RevokedAt
		t.RevokedAt = &revokedAt
	}
	return t
}
