package domain

import (
	"errors"
	"testing"
	"time"
)

func TestUserValidate(t *testing.T) {
	user := User{
		ID:             "user-1",
		Login:          "alice",
		AuthSalt:       []byte("auth-salt"),
		VaultSalt:      []byte("vault-salt"),
		AuthSecretHash: "hash",
		KDFParams:      []byte(`{"algorithm":"argon2id"}`),
	}

	if err := user.Validate(); err != nil {
		t.Fatalf("Validate returned error: %v", err)
	}
}

func TestUserValidateRejectsInvalidKDFJSON(t *testing.T) {
	user := User{
		ID:             "user-1",
		Login:          "alice",
		AuthSalt:       []byte("auth-salt"),
		VaultSalt:      []byte("vault-salt"),
		AuthSecretHash: "hash",
		KDFParams:      []byte(`{`),
	}

	if err := user.Validate(); !errors.Is(err, ErrValidation) {
		t.Fatalf("Validate error = %v, want ErrValidation", err)
	}
}

func TestRefreshTokenValidate(t *testing.T) {
	token := RefreshToken{
		ID:        "token-1",
		UserID:    "user-1",
		TokenHash: []byte("hash"),
		ClientID:  "client-1",
		ExpiresAt: time.Now().Add(time.Hour),
	}

	if err := token.Validate(); err != nil {
		t.Fatalf("Validate returned error: %v", err)
	}
}

func TestRefreshTokenValidateRejectsMissingExpiry(t *testing.T) {
	token := RefreshToken{
		ID:        "token-1",
		UserID:    "user-1",
		TokenHash: []byte("hash"),
		ClientID:  "client-1",
	}

	if err := token.Validate(); !errors.Is(err, ErrValidation) {
		t.Fatalf("Validate error = %v, want ErrValidation", err)
	}
}

func TestUserCloneDeepCopiesBytes(t *testing.T) {
	user := User{
		ID:             "user-1",
		Login:          "alice",
		AuthSalt:       []byte("auth-salt"),
		VaultSalt:      []byte("vault-salt"),
		AuthSecretHash: "hash",
		KDFParams:      []byte(`{"algorithm":"argon2id"}`),
	}

	clone := user.Clone()
	user.AuthSalt[0] = 'X'
	user.VaultSalt[0] = 'Y'
	user.KDFParams[1] = 'Z'

	if string(clone.AuthSalt) != "auth-salt" {
		t.Fatalf("clone.AuthSalt = %q, want original value", string(clone.AuthSalt))
	}
	if string(clone.VaultSalt) != "vault-salt" {
		t.Fatalf("clone.VaultSalt = %q, want original value", string(clone.VaultSalt))
	}
	if string(clone.KDFParams) != `{"algorithm":"argon2id"}` {
		t.Fatalf("clone.KDFParams = %q, want original value", string(clone.KDFParams))
	}
}

func TestRefreshTokenCloneDeepCopiesFields(t *testing.T) {
	revokedAt := time.Now()
	token := RefreshToken{
		ID:        "token-1",
		UserID:    "user-1",
		TokenHash: []byte("hash"),
		ClientID:  "client-1",
		ExpiresAt: time.Now().Add(time.Hour),
		RevokedAt: &revokedAt,
	}

	clone := token.Clone()
	token.TokenHash[0] = 'X'
	token.RevokedAt = nil

	if string(clone.TokenHash) != "hash" {
		t.Fatalf("clone.TokenHash = %q, want original value", string(clone.TokenHash))
	}
	if clone.RevokedAt == nil || !clone.RevokedAt.Equal(revokedAt) {
		t.Fatalf("clone.RevokedAt = %v, want %v", clone.RevokedAt, revokedAt)
	}

	emptyClone := RefreshToken{}.Clone()
	if emptyClone.TokenHash != nil || emptyClone.RevokedAt != nil {
		t.Fatalf("empty clone = %+v, want nil optional fields", emptyClone)
	}
}

func TestVaultItemValidate(t *testing.T) {
	item := VaultItem{
		ID:               "item-1",
		UserID:           "user-1",
		ServerRevision:   1,
		EncryptedPayload: []byte("payload"),
		PayloadNonce:     []byte("nonce"),
		PayloadVersion:   1,
	}

	if err := item.Validate(); err != nil {
		t.Fatalf("Validate returned error: %v", err)
	}
}

func TestVaultItemValidateRejectsNegativeRevision(t *testing.T) {
	item := VaultItem{
		ID:               "item-1",
		UserID:           "user-1",
		ServerRevision:   -1,
		EncryptedPayload: []byte("payload"),
		PayloadNonce:     []byte("nonce"),
		PayloadVersion:   1,
	}

	if err := item.Validate(); !errors.Is(err, ErrValidation) {
		t.Fatalf("Validate error = %v, want ErrValidation", err)
	}
}

func TestVaultItemValidateRejectsInvalidPayloadVersion(t *testing.T) {
	item := VaultItem{
		ID:               "item-1",
		UserID:           "user-1",
		ServerRevision:   1,
		EncryptedPayload: []byte("payload"),
		PayloadNonce:     []byte("nonce"),
	}

	if err := item.Validate(); !errors.Is(err, ErrValidation) {
		t.Fatalf("Validate error = %v, want ErrValidation", err)
	}
}

func TestVaultItemCloneDeepCopiesFields(t *testing.T) {
	deletedAt := time.Now()
	item := VaultItem{
		ID:               "item-1",
		UserID:           "user-1",
		ServerRevision:   1,
		EncryptedPayload: []byte("payload"),
		PayloadNonce:     []byte("nonce"),
		PayloadVersion:   1,
		DeletedAt:        &deletedAt,
	}

	clone := item.Clone()
	item.EncryptedPayload[0] = 'X'
	item.PayloadNonce[0] = 'Y'
	item.DeletedAt = nil

	if string(clone.EncryptedPayload) != "payload" {
		t.Fatalf("clone.EncryptedPayload = %q, want original value", string(clone.EncryptedPayload))
	}
	if string(clone.PayloadNonce) != "nonce" {
		t.Fatalf("clone.PayloadNonce = %q, want original value", string(clone.PayloadNonce))
	}
	if clone.DeletedAt == nil || !clone.DeletedAt.Equal(deletedAt) {
		t.Fatalf("clone.DeletedAt = %v, want %v", clone.DeletedAt, deletedAt)
	}
}

func TestSyncStateValidate(t *testing.T) {
	state := SyncState{UserID: "user-1", CurrentRevision: 1}

	if err := state.Validate(); err != nil {
		t.Fatalf("Validate returned error: %v", err)
	}
}

func TestSyncStateValidateRejectsNegativeRevision(t *testing.T) {
	state := SyncState{UserID: "user-1", CurrentRevision: -1}

	if err := state.Validate(); !errors.Is(err, ErrValidation) {
		t.Fatalf("Validate error = %v, want ErrValidation", err)
	}
}
