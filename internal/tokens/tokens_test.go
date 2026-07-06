package tokens

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func testService(t *testing.T) *Service {
	t.Helper()

	service, err := NewService(Config{
		Issuer:       "test-issuer",
		AccessSecret: bytes.Repeat([]byte{1}, 32),
		AccessTTL:    time.Minute,
		RefreshTTL:   time.Hour,
		Now: func() time.Time {
			return time.Date(2026, 7, 2, 20, 0, 0, 0, time.UTC)
		},
	})
	if err != nil {
		t.Fatalf("NewService returned error: %v", err)
	}
	return service
}

func TestNewServiceValidatesConfig(t *testing.T) {
	if _, err := NewService(Config{}); err == nil {
		t.Fatal("NewService returned nil error for empty config")
	}

	if _, err := NewService(Config{
		AccessSecret: bytes.Repeat([]byte{1}, 32),
		AccessTTL:    time.Minute,
		RefreshTTL:   time.Hour,
	}); err != nil {
		t.Fatalf("NewService returned error for valid config: %v", err)
	}
}

func TestIssuePairAndVerifyAccess(t *testing.T) {
	service := testService(t)

	pair, err := service.IssuePair("user-1", "client-1")
	if err != nil {
		t.Fatalf("IssuePair returned error: %v", err)
	}
	if pair.AccessToken == "" || pair.RefreshToken == "" {
		t.Fatalf("issued empty tokens: %+v", pair)
	}
	if len(pair.RefreshTokenHash) != 32 {
		t.Fatalf("len(RefreshTokenHash) = %d, want 32", len(pair.RefreshTokenHash))
	}

	principal, err := service.VerifyAccess(pair.AccessToken)
	if err != nil {
		t.Fatalf("VerifyAccess returned error: %v", err)
	}
	if principal.UserID != "user-1" || principal.ClientID != "client-1" {
		t.Fatalf("principal = %+v, want issued user/client", principal)
	}
	if principal.Issuer != "test-issuer" {
		t.Fatalf("issuer = %q, want test-issuer", principal.Issuer)
	}
}

func TestIssuePairRejectsMissingPrincipal(t *testing.T) {
	service := testService(t)

	if _, err := service.IssuePair("", "client-1"); err == nil {
		t.Fatal("IssuePair returned nil error for empty user id")
	}
	if _, err := service.IssuePair("user-1", ""); err == nil {
		t.Fatal("IssuePair returned nil error for empty client id")
	}
}

func TestVerifyAccessRejectsInvalidToken(t *testing.T) {
	service := testService(t)

	if _, err := service.VerifyAccess(""); err == nil {
		t.Fatal("VerifyAccess returned nil error for empty token")
	}
	if _, err := service.VerifyAccess("not-a-jwt"); err == nil {
		t.Fatal("VerifyAccess returned nil error for invalid token")
	}
}

func TestHashRefreshTokenTrimsAndIsDeterministic(t *testing.T) {
	first := HashRefreshToken(" token ")
	second := HashRefreshToken("token")

	if !bytes.Equal(first, second) {
		t.Fatal("HashRefreshToken should trim surrounding whitespace")
	}
	if strings.Contains(string(first), "token") {
		t.Fatal("hash contains raw token material")
	}
}
