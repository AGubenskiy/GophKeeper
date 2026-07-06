package clientcrypto

import (
	"bytes"
	"testing"

	"github.com/AGubenskiy/GophKeeper/internal/cryptoutil"
)

func TestDeriveAuthSecretDeterministic(t *testing.T) {
	password := []byte("correct horse battery staple")

	first, err := DeriveAuthSecret(password, "http://localhost:8080/", "Alice")
	if err != nil {
		t.Fatalf("DeriveAuthSecret returned error: %v", err)
	}
	second, err := DeriveAuthSecret(password, "http://localhost:8080", "alice")
	if err != nil {
		t.Fatalf("DeriveAuthSecret returned error: %v", err)
	}

	if !bytes.Equal(first, second) {
		t.Fatal("DeriveAuthSecret should normalize login and server URL")
	}
	if len(first) != cryptoutil.KeyLength32 {
		t.Fatalf("len(secret) = %d, want %d", len(first), cryptoutil.KeyLength32)
	}
}

func TestDeriveAuthSecretSeparatesContext(t *testing.T) {
	password := []byte("correct horse battery staple")

	first, err := DeriveAuthSecret(password, "http://localhost:8080", "alice")
	if err != nil {
		t.Fatalf("DeriveAuthSecret returned error: %v", err)
	}
	second, err := DeriveAuthSecret(password, "http://localhost:8081", "alice")
	if err != nil {
		t.Fatalf("DeriveAuthSecret returned error: %v", err)
	}

	if bytes.Equal(first, second) {
		t.Fatal("different server URLs produced identical auth secrets")
	}
}

func TestDeriveAuthSecretValidatesInput(t *testing.T) {
	if _, err := DeriveAuthSecret(nil, "http://localhost:8080", "alice"); err == nil {
		t.Fatal("DeriveAuthSecret returned nil error for empty password")
	}
	if _, err := DeriveAuthSecret([]byte("password"), "localhost:8080", "alice"); err == nil {
		t.Fatal("DeriveAuthSecret returned nil error for invalid server URL")
	}
	if _, err := DeriveAuthSecret([]byte("password"), "http://localhost:8080", " "); err == nil {
		t.Fatal("DeriveAuthSecret returned nil error for empty login")
	}
}

func TestDeriveVaultKeyDeterministicAndSeparated(t *testing.T) {
	params := cryptoutil.KDFParams{
		Algorithm:   cryptoutil.KDFAlgorithmArgon2id,
		MemoryKiB:   8,
		Iterations:  1,
		Parallelism: 1,
		KeyLength:   cryptoutil.KeyLength32,
	}
	password := []byte("correct horse battery staple")
	salt := bytes.Repeat([]byte{4}, 16)

	first, err := DeriveVaultKey(password, salt, params)
	if err != nil {
		t.Fatalf("DeriveVaultKey returned error: %v", err)
	}
	second, err := DeriveVaultKey(password, salt, params)
	if err != nil {
		t.Fatalf("DeriveVaultKey returned error: %v", err)
	}
	root, err := cryptoutil.DeriveKey(password, salt, params)
	if err != nil {
		t.Fatalf("DeriveKey returned error: %v", err)
	}

	if !bytes.Equal(first, second) {
		t.Fatal("DeriveVaultKey is not deterministic")
	}
	if bytes.Equal(first, root) {
		t.Fatal("DeriveVaultKey returned the raw KDF root key")
	}
	if len(first) != cryptoutil.KeyLength32 {
		t.Fatalf("len(key) = %d, want %d", len(first), cryptoutil.KeyLength32)
	}
}
