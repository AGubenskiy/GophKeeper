package cryptoutil

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
)

const gcmNonceSize = 12

// EncryptAESGCM encrypts plaintext with AES-256-GCM and returns ciphertext plus nonce.
func EncryptAESGCM(key, plaintext, aad []byte) ([]byte, []byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, nil, err
	}

	nonce, err := RandomBytes(gcmNonceSize)
	if err != nil {
		return nil, nil, err
	}

	ciphertext := gcm.Seal(nil, nonce, plaintext, aad)
	return ciphertext, nonce, nil
}

// DecryptAESGCM decrypts ciphertext with AES-256-GCM.
func DecryptAESGCM(key, ciphertext, nonce, aad []byte) ([]byte, error) {
	if len(ciphertext) == 0 {
		return nil, fmt.Errorf("ciphertext is required")
	}

	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	if len(nonce) != gcm.NonceSize() {
		return nil, fmt.Errorf("nonce must be %d bytes", gcm.NonceSize())
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("decrypt payload: %w", err)
	}
	return plaintext, nil
}

// VaultItemAAD returns associated data for encrypted vault item payloads.
func VaultItemAAD(userID, itemID string, payloadVersion int16) []byte {
	const prefix = "gophkeeper:vault-item:v1"
	size := len(prefix) + 1 + len(userID) + 1 + len(itemID) + 1 + 2
	out := make([]byte, 0, size)
	out = append(out, prefix...)
	out = append(out, 0)
	out = append(out, userID...)
	out = append(out, 0)
	out = append(out, itemID...)
	out = append(out, 0)
	var version [2]byte
	binary.BigEndian.PutUint16(version[:], uint16(payloadVersion))
	out = append(out, version[:]...)
	return out
}

func newGCM(key []byte) (cipher.AEAD, error) {
	if len(key) != KeyLength32 {
		return nil, fmt.Errorf("aes-gcm key must be %d bytes", KeyLength32)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create aes cipher: %w", err)
	}
	gcm, err := cipher.NewGCMWithNonceSize(block, gcmNonceSize)
	if err != nil {
		return nil, fmt.Errorf("create gcm: %w", err)
	}
	return gcm, nil
}
