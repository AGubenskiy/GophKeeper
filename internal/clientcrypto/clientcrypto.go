package clientcrypto

import (
	"crypto/sha256"
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/AGubenskiy/GophKeeper/internal/cryptoutil"
)

const authSecretPurpose = "gophkeeper-client-auth-secret-v1"

const vaultKeyPurpose = "vault"

// DeriveAuthSecret derives a stable authentication secret from the master password.
//
// The server never receives the raw master password. It receives this derived
// auth secret and stores only a separate server-side verifier for it.
func DeriveAuthSecret(masterPassword []byte, serverURL, login string) ([]byte, error) {
	if len(masterPassword) == 0 {
		return nil, fmt.Errorf("master password is required")
	}

	normalizedServerURL, err := normalizeServerURL(serverURL)
	if err != nil {
		return nil, err
	}
	login = strings.TrimSpace(strings.ToLower(login))
	if login == "" {
		return nil, fmt.Errorf("login is required")
	}

	saltMaterial := sha256.Sum256([]byte(authSecretPurpose + "\x00" + normalizedServerURL + "\x00" + login))
	salt := saltMaterial[:16]
	params := cryptoutil.DefaultKDFParams()
	return cryptoutil.DeriveKey(masterPassword, salt, params)
}

// DeriveVaultKey derives the local client-side vault encryption key.
func DeriveVaultKey(masterPassword, vaultSalt []byte, params cryptoutil.KDFParams) ([]byte, error) {
	rootKey, err := cryptoutil.DeriveKey(masterPassword, vaultSalt, params)
	if err != nil {
		return nil, err
	}
	defer cryptoutil.Zero(rootKey)

	return cryptoutil.DeriveSubkey(rootKey, vaultKeyPurpose, cryptoutil.KeyLength32)
}

func normalizeServerURL(rawURL string) (string, error) {
	trimmed := strings.TrimSpace(rawURL)
	if trimmed == "" {
		return "", fmt.Errorf("server url is required")
	}
	parsed, err := url.Parse(trimmed)
	if err != nil {
		return "", fmt.Errorf("parse server url: %w", err)
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return "", fmt.Errorf("server url must include scheme and host")
	}
	if err := validateServerTransport(parsed); err != nil {
		return "", err
	}
	parsed.Path = strings.TrimRight(parsed.Path, "/")
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed.String(), nil
}

func validateServerTransport(parsed *url.URL) error {
	switch strings.ToLower(parsed.Scheme) {
	case "https":
		return nil
	case "http":
		if isLoopbackHost(parsed.Hostname()) {
			return nil
		}
		return fmt.Errorf("server url must use https outside localhost")
	default:
		return fmt.Errorf("server url must use http or https")
	}
}

func isLoopbackHost(host string) bool {
	host = strings.Trim(strings.ToLower(strings.TrimSpace(host)), "[]")
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
