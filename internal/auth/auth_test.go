package auth

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/AGubenskiy/GophKeeper/internal/cryptoutil"
	"github.com/AGubenskiy/GophKeeper/internal/domain"
	"github.com/AGubenskiy/GophKeeper/internal/tokens"
)

func TestRegisterLoginRefreshAndLogout(t *testing.T) {
	service, users, refreshTokens := newTestService(t)
	ctx := context.Background()
	authSecret := []byte("1234567890abcdef")

	registered, err := service.Register(ctx, "alice", authSecret, "client-1")
	if err != nil {
		t.Fatalf("Register returned error: %v", err)
	}
	if registered.User.ID == "" || registered.AccessToken == "" || registered.RefreshToken == "" {
		t.Fatalf("Register returned incomplete session: %+v", registered)
	}
	if len(users.byLogin["alice"].AuthSecretHash) == 0 {
		t.Fatal("stored user has empty auth hash")
	}

	params, err := service.AuthParams(ctx, "alice")
	if err != nil {
		t.Fatalf("AuthParams returned error: %v", err)
	}
	if params.Login != "alice" || len(params.AuthSalt) == 0 || len(params.VaultSalt) == 0 {
		t.Fatalf("AuthParams returned incomplete params: %+v", params)
	}

	loggedIn, err := service.Login(ctx, "alice", authSecret, "client-1")
	if err != nil {
		t.Fatalf("Login returned error: %v", err)
	}
	if loggedIn.User.ID != registered.User.ID || loggedIn.RefreshToken == registered.RefreshToken {
		t.Fatalf("Login session = %+v, want same user and new refresh token", loggedIn)
	}

	refreshed, err := service.Refresh(ctx, loggedIn.RefreshToken)
	if err != nil {
		t.Fatalf("Refresh returned error: %v", err)
	}
	if refreshed.User.ID != registered.User.ID || refreshed.RefreshToken == loggedIn.RefreshToken {
		t.Fatalf("Refresh session = %+v, want same user and rotated refresh token", refreshed)
	}

	if err = service.Logout(ctx, refreshed.RefreshToken); err != nil {
		t.Fatalf("Logout returned error: %v", err)
	}
	stored := refreshTokens.byHash[string(tokens.HashRefreshToken(refreshed.RefreshToken))]
	if stored.RevokedAt == nil {
		t.Fatal("Logout did not revoke refresh token")
	}
}

func TestRegisterRejectsInvalidInput(t *testing.T) {
	service, _, _ := newTestService(t)

	if _, err := service.Register(context.Background(), "", []byte("1234567890abcdef"), "client-1"); !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("Register error = %v, want ErrValidation", err)
	}
	if _, err := service.Register(context.Background(), "alice", []byte("short"), "client-1"); !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("Register error = %v, want ErrValidation", err)
	}
	if _, err := service.Register(context.Background(), "alice", []byte("1234567890abcdef"), ""); !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("Register error = %v, want ErrValidation", err)
	}
}

func TestLoginRejectsInvalidCredentials(t *testing.T) {
	service, _, _ := newTestService(t)
	ctx := context.Background()
	authSecret := []byte("1234567890abcdef")

	if _, err := service.Register(ctx, "alice", authSecret, "client-1"); err != nil {
		t.Fatalf("Register returned error: %v", err)
	}

	if _, err := service.Login(ctx, "alice", []byte("wrong-wrong-wrong"), "client-1"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("Login error = %v, want ErrInvalidCredentials", err)
	}
	if _, err := service.Login(ctx, "missing", authSecret, "client-1"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("Login error = %v, want ErrInvalidCredentials", err)
	}
}

func TestRefreshRejectsExpiredAndRevokedTokens(t *testing.T) {
	service, _, refreshTokens := newTestService(t)
	ctx := context.Background()

	session, err := service.Register(ctx, "alice", []byte("1234567890abcdef"), "client-1")
	if err != nil {
		t.Fatalf("Register returned error: %v", err)
	}

	stored := refreshTokens.byHash[string(tokens.HashRefreshToken(session.RefreshToken))]
	revokedAt := testNow()
	stored.RevokedAt = &revokedAt
	refreshTokens.byHash[string(stored.TokenHash)] = stored
	if _, err = service.Refresh(ctx, session.RefreshToken); !errors.Is(err, ErrInvalidRefreshToken) {
		t.Fatalf("Refresh revoked error = %v, want ErrInvalidRefreshToken", err)
	}

	session, err = service.Login(ctx, "alice", []byte("1234567890abcdef"), "client-1")
	if err != nil {
		t.Fatalf("Login returned error: %v", err)
	}
	stored = refreshTokens.byHash[string(tokens.HashRefreshToken(session.RefreshToken))]
	stored.ExpiresAt = testNow().Add(-time.Minute)
	refreshTokens.byHash[string(stored.TokenHash)] = stored
	if _, err = service.Refresh(ctx, session.RefreshToken); !errors.Is(err, ErrInvalidRefreshToken) {
		t.Fatalf("Refresh expired error = %v, want ErrInvalidRefreshToken", err)
	}
}

func TestLogoutRejectsUnknownToken(t *testing.T) {
	service, _, _ := newTestService(t)

	if err := service.Logout(context.Background(), "missing"); !errors.Is(err, ErrInvalidRefreshToken) {
		t.Fatalf("Logout error = %v, want ErrInvalidRefreshToken", err)
	}
}

func TestNewServiceValidatesConfig(t *testing.T) {
	_, err := NewService(Config{})
	if err == nil {
		t.Fatal("NewService returned nil error for empty config")
	}
}

func newTestService(t *testing.T) (*Service, *fakeUsers, *fakeRefreshTokens) {
	t.Helper()

	users := newFakeUsers()
	refreshTokens := newFakeRefreshTokens()
	tokenService, err := tokens.NewService(tokens.Config{
		Issuer:       "test",
		AccessSecret: []byte("12345678901234567890123456789012"),
		AccessTTL:    time.Minute,
		RefreshTTL:   time.Hour,
		Now:          testNow,
	})
	if err != nil {
		t.Fatalf("tokens.NewService returned error: %v", err)
	}

	nextID := 0
	service, err := NewService(Config{
		Users:         users,
		RefreshTokens: refreshTokens,
		Tokens:        tokenService,
		KDFParams: cryptoutil.KDFParams{
			Algorithm:   cryptoutil.KDFAlgorithmArgon2id,
			MemoryKiB:   8,
			Iterations:  1,
			Parallelism: 1,
			KeyLength:   cryptoutil.KeyLength32,
		},
		SaltBytes: 16,
		NewID: func() string {
			nextID++
			return "id-" + string(rune('0'+nextID))
		},
		Now: testNow,
	})
	if err != nil {
		t.Fatalf("NewService returned error: %v", err)
	}
	return service, users, refreshTokens
}

func testNow() time.Time {
	return time.Date(2026, 7, 2, 20, 0, 0, 0, time.UTC)
}

type fakeUsers struct {
	byID    map[string]domain.User
	byLogin map[string]domain.User
}

func newFakeUsers() *fakeUsers {
	return &fakeUsers{
		byID:    make(map[string]domain.User),
		byLogin: make(map[string]domain.User),
	}
}

func (f *fakeUsers) Create(_ context.Context, user domain.User) error {
	if _, ok := f.byLogin[user.Login]; ok {
		return domain.ErrAlreadyExists
	}
	f.byID[user.ID] = user.Clone()
	f.byLogin[user.Login] = user.Clone()
	return nil
}

func (f *fakeUsers) FindByLogin(_ context.Context, login string) (domain.User, error) {
	user, ok := f.byLogin[login]
	if !ok {
		return domain.User{}, domain.ErrNotFound
	}
	return user.Clone(), nil
}

func (f *fakeUsers) FindByID(_ context.Context, id string) (domain.User, error) {
	user, ok := f.byID[id]
	if !ok {
		return domain.User{}, domain.ErrNotFound
	}
	return user.Clone(), nil
}

type fakeRefreshTokens struct {
	byHash map[string]domain.RefreshToken
}

func newFakeRefreshTokens() *fakeRefreshTokens {
	return &fakeRefreshTokens{
		byHash: make(map[string]domain.RefreshToken),
	}
}

func (f *fakeRefreshTokens) Create(_ context.Context, token domain.RefreshToken) error {
	token = token.Clone()
	f.byHash[string(token.TokenHash)] = token
	return nil
}

func (f *fakeRefreshTokens) FindByHash(_ context.Context, hash []byte) (domain.RefreshToken, error) {
	token, ok := f.byHash[string(hash)]
	if !ok {
		return domain.RefreshToken{}, domain.ErrNotFound
	}
	return token.Clone(), nil
}

func (f *fakeRefreshTokens) Revoke(_ context.Context, id string, revokedAt time.Time) error {
	for hash, token := range f.byHash {
		if token.ID != id {
			continue
		}
		token.RevokedAt = &revokedAt
		f.byHash[hash] = token
		return nil
	}
	return domain.ErrNotFound
}
