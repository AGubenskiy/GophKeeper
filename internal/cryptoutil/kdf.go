package cryptoutil

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"
)

const (
	// KDFAlgorithmArgon2id is the supported password KDF algorithm name.
	KDFAlgorithmArgon2id = "argon2id"
	// KeyLength32 is the default 256-bit key length.
	KeyLength32 = 32
)

// KDFParams describes Argon2id key-derivation settings.
type KDFParams struct {
	Algorithm   string `json:"algorithm"`
	MemoryKiB   uint32 `json:"memory_kib"`
	Iterations  uint32 `json:"iterations"`
	Parallelism uint8  `json:"parallelism"`
	KeyLength   uint32 `json:"key_length"`
}

// DefaultKDFParams returns production-oriented Argon2id parameters.
func DefaultKDFParams() KDFParams {
	return KDFParams{
		Algorithm:   KDFAlgorithmArgon2id,
		MemoryKiB:   64 * 1024,
		Iterations:  3,
		Parallelism: 4,
		KeyLength:   KeyLength32,
	}
}

// Validate checks KDF parameters for supported and safe values.
func (p KDFParams) Validate() error {
	if strings.TrimSpace(p.Algorithm) != KDFAlgorithmArgon2id {
		return fmt.Errorf("unsupported kdf algorithm %q", p.Algorithm)
	}
	if p.MemoryKiB < 8 {
		return fmt.Errorf("kdf memory must be at least 8 KiB")
	}
	if p.Iterations == 0 {
		return fmt.Errorf("kdf iterations must be positive")
	}
	if p.Parallelism == 0 {
		return fmt.Errorf("kdf parallelism must be positive")
	}
	if p.KeyLength == 0 || p.KeyLength > 64 {
		return fmt.Errorf("kdf key length must be between 1 and 64 bytes")
	}
	return nil
}

// MarshalKDFParams encodes KDF parameters as stable JSON.
func MarshalKDFParams(params KDFParams) ([]byte, error) {
	if err := params.Validate(); err != nil {
		return nil, err
	}
	data, err := json.Marshal(params)
	if err != nil {
		return nil, fmt.Errorf("marshal kdf params: %w", err)
	}
	return data, nil
}

// ParseKDFParams decodes and validates KDF parameters.
func ParseKDFParams(data []byte) (KDFParams, error) {
	var params KDFParams
	if err := json.Unmarshal(data, &params); err != nil {
		return KDFParams{}, fmt.Errorf("decode kdf params: %w", err)
	}
	if err := params.Validate(); err != nil {
		return KDFParams{}, err
	}
	return params, nil
}

// DeriveKey derives a key from secret and salt using Argon2id.
func DeriveKey(secret, salt []byte, params KDFParams) ([]byte, error) {
	if len(secret) == 0 {
		return nil, fmt.Errorf("secret is required")
	}
	if len(salt) < 16 {
		return nil, fmt.Errorf("salt must be at least 16 bytes")
	}
	if err := params.Validate(); err != nil {
		return nil, err
	}

	key := argon2.IDKey(secret, salt, params.Iterations, params.MemoryKiB, params.Parallelism, params.KeyLength)
	return key, nil
}

// DeriveSubkey derives a domain-separated subkey from rootKey using HKDF-SHA256.
func DeriveSubkey(rootKey []byte, purpose string, length int) ([]byte, error) {
	if len(rootKey) == 0 {
		return nil, fmt.Errorf("root key is required")
	}
	if strings.TrimSpace(purpose) == "" {
		return nil, fmt.Errorf("subkey purpose is required")
	}
	if length <= 0 || length > 64 {
		return nil, fmt.Errorf("subkey length must be between 1 and 64 bytes")
	}

	reader := hkdf.New(sha256.New, rootKey, nil, []byte("gophkeeper:"+purpose))
	out := make([]byte, length)
	if _, err := io.ReadFull(reader, out); err != nil {
		return nil, fmt.Errorf("derive subkey: %w", err)
	}
	return out, nil
}

// HashAuthSecret derives and encodes the server-side verifier for an auth secret.
func HashAuthSecret(authSecret, salt []byte, params KDFParams) (string, error) {
	key, err := DeriveKey(authSecret, salt, params)
	if err != nil {
		return "", err
	}
	return base64.RawStdEncoding.EncodeToString(key), nil
}

// VerifyAuthSecret verifies authSecret against an encoded server-side verifier.
func VerifyAuthSecret(authSecret, salt []byte, params KDFParams, expectedHash string) (bool, error) {
	expectedHash = strings.TrimSpace(expectedHash)
	if expectedHash == "" {
		return false, fmt.Errorf("expected auth secret hash is required")
	}

	actual, err := HashAuthSecret(authSecret, salt, params)
	if err != nil {
		return false, err
	}

	return hmac.Equal([]byte(actual), []byte(expectedHash)), nil
}

// EqualBytes compares two byte slices in constant time.
func EqualBytes(a, b []byte) bool {
	return hmac.Equal(a, b)
}

// Zero overwrites a byte slice with zeros.
func Zero(data []byte) {
	for i := range data {
		data[i] = 0
	}
}
