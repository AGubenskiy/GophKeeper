package httpapi

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/AGubenskiy/GophKeeper/internal/tokens"
)

func TestAuthMiddlewareStoresPrincipal(t *testing.T) {
	verifier := fakeVerifier{
		principal: tokens.Principal{UserID: "user-1", ClientID: "client-1"},
	}
	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		principal, ok := PrincipalFromContext(r.Context())
		if !ok {
			t.Fatal("principal missing from request context")
		}
		if principal.UserID != "user-1" || principal.ClientID != "client-1" {
			t.Fatalf("principal = %+v, want verifier principal", principal)
		}
		w.WriteHeader(http.StatusNoContent)
	})
	handler := AuthMiddleware(verifier)(next)

	request := httptest.NewRequest(http.MethodGet, "/private", nil)
	request.Header.Set("Authorization", "Bearer token")
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if !nextCalled {
		t.Fatal("next handler was not called")
	}
	if response.Code != http.StatusNoContent {
		t.Fatalf("status code = %d, want %d", response.Code, http.StatusNoContent)
	}
}

func TestAuthMiddlewareRejectsMissingToken(t *testing.T) {
	handler := AuthMiddleware(fakeVerifier{})(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("next handler should not be called")
	}))
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/private", nil))

	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status code = %d, want %d", response.Code, http.StatusUnauthorized)
	}
}

func TestAuthMiddlewareRejectsInvalidToken(t *testing.T) {
	handler := AuthMiddleware(fakeVerifier{err: errors.New("invalid")})(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("next handler should not be called")
	}))
	request := httptest.NewRequest(http.MethodGet, "/private", nil)
	request.Header.Set("Authorization", "Bearer token")
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status code = %d, want %d", response.Code, http.StatusUnauthorized)
	}
}

func TestAuthMiddlewareRejectsNilVerifier(t *testing.T) {
	handler := AuthMiddleware(nil)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("next handler should not be called")
	}))
	request := httptest.NewRequest(http.MethodGet, "/private", nil)
	request.Header.Set("Authorization", "Bearer token")
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status code = %d, want %d", response.Code, http.StatusInternalServerError)
	}
}

type fakeVerifier struct {
	principal tokens.Principal
	err       error
}

func (f fakeVerifier) VerifyAccess(string) (tokens.Principal, error) {
	if f.err != nil {
		return tokens.Principal{}, f.err
	}
	return f.principal, nil
}
