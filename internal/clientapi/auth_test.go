package clientapi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/AGubenskiy/GophKeeper/internal/cryptoutil"
)

func TestClientRegisterLoginRefreshLogout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/auth/register":
			if r.Method != http.MethodPost {
				t.Fatalf("register method = %s, want POST", r.Method)
			}
			writeTestSession(t, w, http.StatusCreated)
		case "/api/v1/auth/login":
			writeTestSession(t, w, http.StatusOK)
		case "/api/v1/auth/refresh":
			writeTestSession(t, w, http.StatusOK)
		case "/api/v1/auth/logout":
			w.WriteHeader(http.StatusNoContent)
		case "/api/v1/auth/params":
			if r.URL.Query().Get("login") != "alice" {
				t.Fatalf("login query = %q, want alice", r.URL.Query().Get("login"))
			}
			writeJSON(t, w, http.StatusOK, AuthParams{
				Login:     "alice",
				AuthSalt:  base64.StdEncoding.EncodeToString([]byte("auth-salt")),
				VaultSalt: base64.StdEncoding.EncodeToString([]byte("vault-salt")),
				KDFParams: fastKDFParams(),
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client, err := New(server.URL, server.Client())
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}

	session, err := client.Register(context.Background(), NewCredentialsRequest("alice", []byte("auth-secret"), "client-1"))
	if err != nil {
		t.Fatalf("Register returned error: %v", err)
	}
	if session.UserID != "user-1" || session.AccessToken == "" {
		t.Fatalf("Register session = %+v, want populated session", session)
	}

	if _, err = client.Login(context.Background(), NewCredentialsRequest("alice", []byte("auth-secret"), "client-1")); err != nil {
		t.Fatalf("Login returned error: %v", err)
	}
	if _, err = client.Refresh(context.Background(), "refresh-token"); err != nil {
		t.Fatalf("Refresh returned error: %v", err)
	}
	if err = client.Logout(context.Background(), "refresh-token"); err != nil {
		t.Fatalf("Logout returned error: %v", err)
	}

	params, err := client.AuthParams(context.Background(), "alice")
	if err != nil {
		t.Fatalf("AuthParams returned error: %v", err)
	}
	authSalt, err := params.AuthSaltBytes()
	if err != nil {
		t.Fatalf("AuthSaltBytes returned error: %v", err)
	}
	if string(authSalt) != "auth-salt" {
		t.Fatalf("authSalt = %q, want auth-salt", authSalt)
	}
}

func TestClientDecodesAPIError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusUnauthorized, map[string]any{
			"error": map[string]string{
				"code":       "invalid_credentials",
				"message":    "invalid credentials",
				"request_id": "req-1",
			},
		})
	}))
	defer server.Close()

	client, err := New(server.URL, server.Client())
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}

	_, err = client.Login(context.Background(), NewCredentialsRequest("alice", []byte("auth-secret"), "client-1"))
	var apiErr *Error
	if !errors.As(err, &apiErr) {
		t.Fatalf("Login error = %v, want *Error", err)
	}
	if apiErr.StatusCode != http.StatusUnauthorized || apiErr.Code != "invalid_credentials" || apiErr.RequestID != "req-1" {
		t.Fatalf("api error = %+v, want decoded error", apiErr)
	}
}

func TestNewRejectsInvalidServerURL(t *testing.T) {
	if _, err := New("", nil); err == nil {
		t.Fatal("New returned nil error for empty URL")
	}
	if _, err := New("localhost:8080", nil); err == nil {
		t.Fatal("New returned nil error for URL without scheme")
	}
	if _, err := New("ftp://localhost:8080", nil); err == nil {
		t.Fatal("New returned nil error for unsupported scheme")
	}
	if _, err := New("http://server.local", nil); err == nil {
		t.Fatal("New returned nil error for non-local HTTP URL")
	}
	if _, err := New("http://localhost:8080", nil); err != nil {
		t.Fatalf("New rejected localhost HTTP URL: %v", err)
	}
	if _, err := New("https://server.local", nil); err != nil {
		t.Fatalf("New rejected HTTPS URL: %v", err)
	}
}

func writeTestSession(t *testing.T, w http.ResponseWriter, status int) {
	t.Helper()
	writeJSON(t, w, status, Session{
		UserID:           "user-1",
		Login:            "alice",
		AccessToken:      "access-token",
		AccessExpiresAt:  time.Date(2026, 7, 3, 10, 0, 0, 0, time.UTC).Add(time.Minute),
		RefreshToken:     "refresh-token",
		RefreshExpiresAt: time.Date(2026, 7, 3, 10, 0, 0, 0, time.UTC).Add(time.Hour),
		AuthSalt:         base64.StdEncoding.EncodeToString([]byte("auth-salt")),
		VaultSalt:        base64.StdEncoding.EncodeToString([]byte("vault-salt")),
		KDFParams:        ptr(fastKDFParams()),
	})
}

func writeJSON(t *testing.T, w http.ResponseWriter, status int, value any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(value); err != nil {
		t.Fatalf("encode response: %v", err)
	}
}

func fastKDFParams() cryptoutil.KDFParams {
	return cryptoutil.KDFParams{
		Algorithm:   cryptoutil.KDFAlgorithmArgon2id,
		MemoryKiB:   8,
		Iterations:  1,
		Parallelism: 1,
		KeyLength:   cryptoutil.KeyLength32,
	}
}

func ptr[T any](value T) *T {
	return &value
}
