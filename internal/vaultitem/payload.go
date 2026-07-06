package vaultitem

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/AGubenskiy/GophKeeper/internal/cryptoutil"
)

// PayloadVersion is the current encrypted vault item payload version.
const PayloadVersion int16 = 1

// Kind identifies a supported secret record type.
type Kind string

const (
	// KindPassword stores a login/password pair.
	KindPassword Kind = "password"
	// KindText stores arbitrary text.
	KindText Kind = "text"
	// KindCard stores bank card details.
	KindCard Kind = "card"
	// KindFile stores binary file content.
	KindFile Kind = "file"
)

const (
	// FieldLogin stores a login for password records.
	FieldLogin = "login"
	// FieldPassword stores a password for password records.
	FieldPassword = "password"
	// FieldText stores text record content.
	FieldText = "text"
	// FieldCardNumber stores the bank card number.
	FieldCardNumber = "card_number"
	// FieldCardHolder stores the bank card holder name.
	FieldCardHolder = "card_holder"
	// FieldCardExpiry stores the bank card expiration value.
	FieldCardExpiry = "card_expiry"
	// FieldCardCVV stores the bank card verification value.
	FieldCardCVV = "card_cvv"
	// FieldFileName stores the original file name.
	FieldFileName = "file_name"
	// FieldFileMediaType stores the file media type.
	FieldFileMediaType = "file_media_type"
	// FieldFileDataBase64 stores file content encoded as base64.
	FieldFileDataBase64 = "file_data_base64"
)

// Payload is the plaintext JSON envelope encrypted inside each vault item.
type Payload struct {
	Version  int16             `json:"version"`
	Kind     Kind              `json:"kind"`
	Title    string            `json:"title"`
	Metadata map[string]string `json:"metadata,omitempty"`
	Fields   map[string]string `json:"fields,omitempty"`
}

// NewPassword creates a password payload.
func NewPassword(title, login string, password []byte, metadata map[string]string) Payload {
	fields := map[string]string{
		FieldPassword: string(password),
	}
	if strings.TrimSpace(login) != "" {
		fields[FieldLogin] = strings.TrimSpace(login)
	}
	return Payload{
		Version:  PayloadVersion,
		Kind:     KindPassword,
		Title:    title,
		Metadata: cloneStringMap(metadata),
		Fields:   fields,
	}
}

// NewText creates a text payload.
func NewText(title string, text []byte, metadata map[string]string) Payload {
	return Payload{
		Version:  PayloadVersion,
		Kind:     KindText,
		Title:    title,
		Metadata: cloneStringMap(metadata),
		Fields: map[string]string{
			FieldText: string(text),
		},
	}
}

// NewCard creates a bank card payload.
func NewCard(title, number, holder, expiry string, cvv []byte, metadata map[string]string) Payload {
	fields := map[string]string{
		FieldCardNumber: strings.TrimSpace(number),
		FieldCardExpiry: strings.TrimSpace(expiry),
	}
	if strings.TrimSpace(holder) != "" {
		fields[FieldCardHolder] = strings.TrimSpace(holder)
	}
	if len(cvv) > 0 {
		fields[FieldCardCVV] = string(cvv)
	}
	return Payload{
		Version:  PayloadVersion,
		Kind:     KindCard,
		Title:    title,
		Metadata: cloneStringMap(metadata),
		Fields:   fields,
	}
}

// NewFile creates a file payload.
func NewFile(title, path, mediaType string, content []byte, metadata map[string]string) Payload {
	fields := map[string]string{
		FieldFileName:       filepath.Base(path),
		FieldFileDataBase64: base64.StdEncoding.EncodeToString(content),
	}
	if strings.TrimSpace(mediaType) != "" {
		fields[FieldFileMediaType] = strings.TrimSpace(mediaType)
	}
	return Payload{
		Version:  PayloadVersion,
		Kind:     KindFile,
		Title:    title,
		Metadata: cloneStringMap(metadata),
		Fields:   fields,
	}
}

// Encrypt encrypts payload for itemID and userID.
func Encrypt(key []byte, userID, itemID string, payload Payload) ([]byte, []byte, error) {
	payload = payload.normalized()
	if err := payload.Validate(); err != nil {
		return nil, nil, err
	}
	if strings.TrimSpace(userID) == "" {
		return nil, nil, errors.New("user id is required")
	}
	if strings.TrimSpace(itemID) == "" {
		return nil, nil, errors.New("item id is required")
	}

	plaintext, err := json.Marshal(payload)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal vault item payload: %w", err)
	}
	return cryptoutil.EncryptAESGCM(key, plaintext, cryptoutil.VaultItemAAD(userID, itemID, PayloadVersion))
}

// Decrypt decrypts and validates a vault item payload.
func Decrypt(key []byte, userID, itemID string, ciphertext, nonce []byte) (Payload, error) {
	if strings.TrimSpace(userID) == "" {
		return Payload{}, errors.New("user id is required")
	}
	if strings.TrimSpace(itemID) == "" {
		return Payload{}, errors.New("item id is required")
	}

	plaintext, err := cryptoutil.DecryptAESGCM(key, ciphertext, nonce, cryptoutil.VaultItemAAD(userID, itemID, PayloadVersion))
	if err != nil {
		return Payload{}, err
	}

	var payload Payload
	if err = json.Unmarshal(plaintext, &payload); err != nil {
		return Payload{}, fmt.Errorf("decode vault item payload: %w", err)
	}
	payload = payload.normalized()
	if err = payload.Validate(); err != nil {
		return Payload{}, err
	}
	return payload, nil
}

// Validate checks that the payload is complete for its kind.
func (p Payload) Validate() error {
	if p.Version != PayloadVersion {
		return fmt.Errorf("unsupported payload version %d", p.Version)
	}
	if strings.TrimSpace(p.Title) == "" {
		return errors.New("title is required")
	}
	if err := validateMetadata(p.Metadata); err != nil {
		return err
	}

	switch p.Kind {
	case KindPassword:
		return requireField(p.Fields, FieldPassword)
	case KindText:
		return requireField(p.Fields, FieldText)
	case KindCard:
		if err := requireField(p.Fields, FieldCardNumber); err != nil {
			return err
		}
		return requireField(p.Fields, FieldCardExpiry)
	case KindFile:
		if err := requireField(p.Fields, FieldFileName); err != nil {
			return err
		}
		if err := requireField(p.Fields, FieldFileDataBase64); err != nil {
			return err
		}
		if _, err := base64.StdEncoding.DecodeString(p.Fields[FieldFileDataBase64]); err != nil {
			return fmt.Errorf("file content must be base64: %w", err)
		}
		return nil
	default:
		return fmt.Errorf("unsupported item kind %q", p.Kind)
	}
}

func (p Payload) normalized() Payload {
	out := Payload{
		Version:  p.Version,
		Kind:     p.Kind,
		Title:    strings.TrimSpace(p.Title),
		Metadata: cloneStringMap(p.Metadata),
		Fields:   cloneStringMap(p.Fields),
	}
	if out.Version == 0 {
		out.Version = PayloadVersion
	}
	return out
}

func validateMetadata(metadata map[string]string) error {
	for key := range metadata {
		if strings.TrimSpace(key) == "" {
			return errors.New("metadata key is required")
		}
	}
	return nil
}

func requireField(fields map[string]string, key string) error {
	if strings.TrimSpace(fields[key]) == "" {
		return fmt.Errorf("%s is required", key)
	}
	return nil
}

func cloneStringMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for key, value := range in {
		out[strings.TrimSpace(key)] = value
	}
	return out
}
