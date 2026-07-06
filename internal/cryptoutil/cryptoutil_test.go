package cryptoutil

import (
	"bytes"
	"testing"
)

func fastKDFParams() KDFParams {
	return KDFParams{
		Algorithm:   KDFAlgorithmArgon2id,
		MemoryKiB:   8,
		Iterations:  1,
		Parallelism: 1,
		KeyLength:   KeyLength32,
	}
}

func TestKDFParamsRoundTrip(t *testing.T) {
	params := fastKDFParams()

	data, err := MarshalKDFParams(params)
	if err != nil {
		t.Fatalf("MarshalKDFParams returned error: %v", err)
	}
	got, err := ParseKDFParams(data)
	if err != nil {
		t.Fatalf("ParseKDFParams returned error: %v", err)
	}
	if got != params {
		t.Fatalf("ParseKDFParams = %+v, want %+v", got, params)
	}
}

func TestDeriveKeyDeterministic(t *testing.T) {
	params := fastKDFParams()
	secret := []byte("master-secret")
	salt := bytes.Repeat([]byte{1}, 16)

	first, err := DeriveKey(secret, salt, params)
	if err != nil {
		t.Fatalf("DeriveKey returned error: %v", err)
	}
	second, err := DeriveKey(secret, salt, params)
	if err != nil {
		t.Fatalf("DeriveKey returned error: %v", err)
	}

	if !bytes.Equal(first, second) {
		t.Fatal("DeriveKey is not deterministic")
	}
	if len(first) != KeyLength32 {
		t.Fatalf("len(key) = %d, want %d", len(first), KeyLength32)
	}
}

func TestDeriveKeyRejectsWeakInputs(t *testing.T) {
	params := fastKDFParams()

	if _, err := DeriveKey(nil, bytes.Repeat([]byte{1}, 16), params); err == nil {
		t.Fatal("DeriveKey returned nil error for empty secret")
	}
	if _, err := DeriveKey([]byte("secret"), []byte("short"), params); err == nil {
		t.Fatal("DeriveKey returned nil error for short salt")
	}
	params.Algorithm = "pbkdf2"
	if _, err := DeriveKey([]byte("secret"), bytes.Repeat([]byte{1}, 16), params); err == nil {
		t.Fatal("DeriveKey returned nil error for unsupported algorithm")
	}
}

func TestDeriveSubkeySeparatesPurposes(t *testing.T) {
	root := bytes.Repeat([]byte{7}, KeyLength32)

	authKey, err := DeriveSubkey(root, "auth", KeyLength32)
	if err != nil {
		t.Fatalf("DeriveSubkey returned error: %v", err)
	}
	vaultKey, err := DeriveSubkey(root, "vault", KeyLength32)
	if err != nil {
		t.Fatalf("DeriveSubkey returned error: %v", err)
	}

	if bytes.Equal(authKey, vaultKey) {
		t.Fatal("different purposes produced the same subkey")
	}
}

func TestAESGCMRoundTrip(t *testing.T) {
	key := bytes.Repeat([]byte{2}, KeyLength32)
	aad := VaultItemAAD("user-1", "item-1", 1)
	plaintext := []byte(`{"kind":"password"}`)

	ciphertext, nonce, err := EncryptAESGCM(key, plaintext, aad)
	if err != nil {
		t.Fatalf("EncryptAESGCM returned error: %v", err)
	}
	if bytes.Equal(ciphertext, plaintext) {
		t.Fatal("ciphertext equals plaintext")
	}

	got, err := DecryptAESGCM(key, ciphertext, nonce, aad)
	if err != nil {
		t.Fatalf("DecryptAESGCM returned error: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("plaintext = %q, want %q", got, plaintext)
	}
}

func TestAESGCMRejectsWrongAAD(t *testing.T) {
	key := bytes.Repeat([]byte{2}, KeyLength32)
	plaintext := []byte("payload")

	ciphertext, nonce, err := EncryptAESGCM(key, plaintext, []byte("aad-1"))
	if err != nil {
		t.Fatalf("EncryptAESGCM returned error: %v", err)
	}

	if _, err = DecryptAESGCM(key, ciphertext, nonce, []byte("aad-2")); err == nil {
		t.Fatal("DecryptAESGCM returned nil error for wrong aad")
	}
}

func TestHashAndVerifyAuthSecret(t *testing.T) {
	params := fastKDFParams()
	salt := bytes.Repeat([]byte{3}, 16)
	secret := []byte("auth-secret")

	hash, err := HashAuthSecret(secret, salt, params)
	if err != nil {
		t.Fatalf("HashAuthSecret returned error: %v", err)
	}
	ok, err := VerifyAuthSecret(secret, salt, params, hash)
	if err != nil {
		t.Fatalf("VerifyAuthSecret returned error: %v", err)
	}
	if !ok {
		t.Fatal("VerifyAuthSecret returned false for matching secret")
	}

	ok, err = VerifyAuthSecret([]byte("wrong"), salt, params, hash)
	if err != nil {
		t.Fatalf("VerifyAuthSecret returned error: %v", err)
	}
	if ok {
		t.Fatal("VerifyAuthSecret returned true for wrong secret")
	}
}

func TestRandomBytesAndZero(t *testing.T) {
	random, err := RandomBytes(16)
	if err != nil {
		t.Fatalf("RandomBytes returned error: %v", err)
	}
	if len(random) != 16 {
		t.Fatalf("len(random) = %d, want 16", len(random))
	}
	Zero(random)
	if !bytes.Equal(random, make([]byte, 16)) {
		t.Fatalf("Zero did not clear bytes: %v", random)
	}
}
