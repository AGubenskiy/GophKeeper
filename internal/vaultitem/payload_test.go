package vaultitem

import (
	"bytes"
	"testing"

	"github.com/AGubenskiy/GophKeeper/internal/cryptoutil"
)

func TestEncryptDecryptPasswordPayload(t *testing.T) {
	key := bytes.Repeat([]byte{1}, cryptoutil.KeyLength32)
	payload := NewPassword("GitHub", "alice", []byte("s3cret"), map[string]string{"url": "https://github.com"})

	ciphertext, nonce, err := Encrypt(key, "user-1", "item-1", payload)
	if err != nil {
		t.Fatalf("Encrypt returned error: %v", err)
	}

	got, err := Decrypt(key, "user-1", "item-1", ciphertext, nonce)
	if err != nil {
		t.Fatalf("Decrypt returned error: %v", err)
	}
	if got.Kind != KindPassword || got.Title != "GitHub" || got.Fields[FieldPassword] != "s3cret" {
		t.Fatalf("payload = %+v, want password payload", got)
	}
	if got.Metadata["url"] != "https://github.com" {
		t.Fatalf("metadata = %+v, want url", got.Metadata)
	}
}

func TestDecryptRejectsWrongAAD(t *testing.T) {
	key := bytes.Repeat([]byte{1}, cryptoutil.KeyLength32)
	payload := NewText("note", []byte("plain text"), nil)

	ciphertext, nonce, err := Encrypt(key, "user-1", "item-1", payload)
	if err != nil {
		t.Fatalf("Encrypt returned error: %v", err)
	}
	if _, err = Decrypt(key, "user-1", "item-2", ciphertext, nonce); err == nil {
		t.Fatal("Decrypt returned nil error for wrong item id")
	}
}

func TestPayloadValidation(t *testing.T) {
	tests := []struct {
		name    string
		payload Payload
	}{
		{name: "missing title", payload: NewText("", []byte("text"), nil)},
		{name: "missing password", payload: Payload{Version: PayloadVersion, Kind: KindPassword, Title: "empty", Fields: map[string]string{}}},
		{name: "missing card number", payload: NewCard("card", "", "", "12/30", nil, nil)},
		{name: "invalid file base64", payload: Payload{Version: PayloadVersion, Kind: KindFile, Title: "file", Fields: map[string]string{FieldFileName: "a.bin", FieldFileDataBase64: "%%%"}}},
		{name: "unsupported kind", payload: Payload{Version: PayloadVersion, Kind: "otp", Title: "totp", Fields: map[string]string{"secret": "x"}}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.payload.Validate(); err == nil {
				t.Fatal("Validate returned nil error")
			}
		})
	}
}
