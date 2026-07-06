package httpapi

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/AGubenskiy/GophKeeper/internal/auth"
	"github.com/AGubenskiy/GophKeeper/internal/cryptoutil"
	"github.com/AGubenskiy/GophKeeper/internal/domain"
)

func TestAuthHandlerParams(t *testing.T) {
	service := newFakeAuthService()
	handler := NewAuthHandler(service)
	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/v1/auth/params?login=alice", nil)
	mux.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status code = %d, want %d; body: %s", response.Code, http.StatusOK, response.Body.String())
	}

	var body authParamsResponse
	decodeResponse(t, response, &body)
	if body.Login != "alice" {
		t.Fatalf("login = %q, want alice", body.Login)
	}
	if body.AuthSalt != base64.StdEncoding.EncodeToString(service.params.AuthSalt) {
		t.Fatalf("auth salt = %q, want encoded salt", body.AuthSalt)
	}
}

func TestAuthHandlerRegister(t *testing.T) {
	service := newFakeAuthService()
	mux := http.NewServeMux()
	NewAuthHandler(service).RegisterRoutes(mux)

	requestBody := map[string]string{
		"login":       "alice",
		"auth_secret": base64.StdEncoding.EncodeToString([]byte("1234567890abcdef")),
		"client_id":   "client-1",
	}
	response := serveJSON(mux, http.MethodPost, "/api/v1/auth/register", requestBody)

	if response.Code != http.StatusCreated {
		t.Fatalf("status code = %d, want %d; body: %s", response.Code, http.StatusCreated, response.Body.String())
	}
	if service.registerLogin != "alice" || !bytes.Equal(service.registerSecret, []byte("1234567890abcdef")) {
		t.Fatalf("register captured login/secret = %q/%q", service.registerLogin, service.registerSecret)
	}

	var body sessionResponse
	decodeResponse(t, response, &body)
	if body.UserID != "user-1" || body.AccessToken == "" || body.RefreshToken == "" {
		t.Fatalf("session response = %+v, want token response", body)
	}
	if body.AuthSalt == "" || body.VaultSalt == "" || body.KDFParams == nil {
		t.Fatalf("session response missing auth params: %+v", body)
	}
}

func TestAuthHandlerLoginRefreshAndLogout(t *testing.T) {
	service := newFakeAuthService()
	mux := http.NewServeMux()
	NewAuthHandler(service).RegisterRoutes(mux)

	loginResponse := serveJSON(mux, http.MethodPost, "/api/v1/auth/login", map[string]string{
		"login":       "alice",
		"auth_secret": base64.StdEncoding.EncodeToString([]byte("1234567890abcdef")),
		"client_id":   "client-1",
	})
	if loginResponse.Code != http.StatusOK {
		t.Fatalf("login status = %d, want %d; body: %s", loginResponse.Code, http.StatusOK, loginResponse.Body.String())
	}

	refreshResponse := serveJSON(mux, http.MethodPost, "/api/v1/auth/refresh", map[string]string{
		"refresh_token": "refresh-token",
	})
	if refreshResponse.Code != http.StatusOK {
		t.Fatalf("refresh status = %d, want %d; body: %s", refreshResponse.Code, http.StatusOK, refreshResponse.Body.String())
	}

	logoutResponse := serveJSON(mux, http.MethodPost, "/api/v1/auth/logout", map[string]string{
		"refresh_token": "refresh-token",
	})
	if logoutResponse.Code != http.StatusNoContent {
		t.Fatalf("logout status = %d, want %d; body: %s", logoutResponse.Code, http.StatusNoContent, logoutResponse.Body.String())
	}
	if service.logoutToken != "refresh-token" {
		t.Fatalf("logout token = %q, want refresh-token", service.logoutToken)
	}
}

func TestAuthHandlerMapsErrors(t *testing.T) {
	service := newFakeAuthService()
	service.loginErr = auth.ErrInvalidCredentials
	mux := http.NewServeMux()
	NewAuthHandler(service).RegisterRoutes(mux)

	response := serveJSON(mux, http.MethodPost, "/api/v1/auth/login", map[string]string{
		"login":       "alice",
		"auth_secret": base64.StdEncoding.EncodeToString([]byte("1234567890abcdef")),
		"client_id":   "client-1",
	})

	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusUnauthorized)
	}
	var body ErrorResponse
	decodeResponse(t, response, &body)
	if body.Error.Code != errorInvalidCredentials {
		t.Fatalf("error code = %q, want %q", body.Error.Code, errorInvalidCredentials)
	}
}

func TestAuthHandlerRejectsInvalidRequests(t *testing.T) {
	mux := http.NewServeMux()
	NewAuthHandler(newFakeAuthService()).RegisterRoutes(mux)

	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/v1/auth/register", bytes.NewBufferString(`{"login":`))
	request.Header.Set(headerRequestID, "req-1")
	mux.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusBadRequest)
	}

	var body ErrorResponse
	decodeResponse(t, response, &body)
	if body.Error.RequestID != "req-1" {
		t.Fatalf("request id = %q, want req-1", body.Error.RequestID)
	}

	response = serveJSON(mux, http.MethodPost, "/api/v1/auth/register", map[string]string{
		"login":       "alice",
		"auth_secret": "not-base64!",
		"client_id":   "client-1",
	})
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusBadRequest)
	}

	response = serveJSON(mux, http.MethodGet, "/api/v1/auth/register", nil)
	if response.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusMethodNotAllowed)
	}
}

func TestAuthHandlerUnavailable(t *testing.T) {
	mux := http.NewServeMux()
	NewAuthHandler(nil).RegisterRoutes(mux)

	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/v1/auth/params?login=alice", nil)
	mux.ServeHTTP(response, request)

	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusServiceUnavailable)
	}
}

func serveJSON(handler http.Handler, method, path string, value any) *httptest.ResponseRecorder {
	var body bytes.Buffer
	if value != nil {
		_ = json.NewEncoder(&body).Encode(value)
	}
	request := httptest.NewRequest(method, path, &body)
	request.Header.Set(headerContentType, contentTypeApplicationJSON)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func decodeResponse(t *testing.T, response *httptest.ResponseRecorder, target any) {
	t.Helper()

	if err := json.Unmarshal(response.Body.Bytes(), target); err != nil {
		t.Fatalf("decode response %q: %v", response.Body.String(), err)
	}
}

type fakeAuthService struct {
	params         auth.Params
	session        auth.Session
	registerLogin  string
	registerSecret []byte
	loginErr       error
	logoutToken    string
}

func newFakeAuthService() *fakeAuthService {
	kdfParams := cryptoutil.KDFParams{
		Algorithm:   cryptoutil.KDFAlgorithmArgon2id,
		MemoryKiB:   8,
		Iterations:  1,
		Parallelism: 1,
		KeyLength:   cryptoutil.KeyLength32,
	}
	kdfJSON, _ := cryptoutil.MarshalKDFParams(kdfParams)
	now := time.Date(2026, 7, 2, 20, 0, 0, 0, time.UTC)
	user := domain.User{
		ID:        "user-1",
		Login:     "alice",
		AuthSalt:  []byte("auth-salt-auth-salt"),
		VaultSalt: []byte("vault-salt-vault-s"),
		KDFParams: kdfJSON,
	}

	return &fakeAuthService{
		params: auth.Params{
			Login:     "alice",
			AuthSalt:  user.AuthSalt,
			VaultSalt: user.VaultSalt,
			KDFParams: kdfParams,
		},
		session: auth.Session{
			User:             user,
			AccessToken:      "access-token",
			AccessExpiresAt:  now.Add(time.Minute),
			RefreshToken:     "refresh-token",
			RefreshExpiresAt: now.Add(time.Hour),
		},
	}
}

func (f *fakeAuthService) AuthParams(context.Context, string) (auth.Params, error) {
	return f.params, nil
}

func (f *fakeAuthService) Register(_ context.Context, login string, authSecret []byte, _ string) (auth.Session, error) {
	f.registerLogin = login
	f.registerSecret = append([]byte(nil), authSecret...)
	return f.session, nil
}

func (f *fakeAuthService) Login(context.Context, string, []byte, string) (auth.Session, error) {
	if f.loginErr != nil {
		return auth.Session{}, f.loginErr
	}
	return f.session, nil
}

func (f *fakeAuthService) Refresh(context.Context, string) (auth.Session, error) {
	return f.session, nil
}

func (f *fakeAuthService) Logout(_ context.Context, refreshToken string) error {
	if refreshToken == "bad" {
		return errors.New("bad token")
	}
	f.logoutToken = refreshToken
	return nil
}
