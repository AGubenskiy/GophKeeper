package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/AGubenskiy/GophKeeper/internal/cryptoutil"
	"github.com/AGubenskiy/GophKeeper/internal/domain"
	"github.com/AGubenskiy/GophKeeper/internal/tokens"
	"github.com/google/uuid"
)

const (
	defaultSaltBytes       = 32
	minAuthSecretByteCount = 16
)

var (
	// ErrInvalidCredentials reports failed authentication without revealing which field failed.
	ErrInvalidCredentials = errors.New("invalid credentials")
	// ErrInvalidRefreshToken reports a missing, expired, or revoked refresh token.
	ErrInvalidRefreshToken = errors.New("invalid refresh token")
)

// UserRepository stores and loads users.
type UserRepository interface {
	Create(ctx context.Context, user domain.User) error
	FindByLogin(ctx context.Context, login string) (domain.User, error)
	FindByID(ctx context.Context, id string) (domain.User, error)
}

// RefreshTokenRepository stores and revokes refresh tokens.
type RefreshTokenRepository interface {
	Create(ctx context.Context, token domain.RefreshToken) error
	FindByHash(ctx context.Context, hash []byte) (domain.RefreshToken, error)
	Revoke(ctx context.Context, id string, revokedAt time.Time) error
}

// TokenIssuer issues access and refresh token pairs.
type TokenIssuer interface {
	IssuePair(userID, clientID string) (tokens.Pair, error)
}

// Config contains auth service dependencies and settings.
type Config struct {
	Users         UserRepository
	RefreshTokens RefreshTokenRepository
	Tokens        TokenIssuer
	KDFParams     cryptoutil.KDFParams
	SaltBytes     int
	NewID         func() string
	Now           func() time.Time
}

// Params contains client KDF parameters and salts needed before login.
type Params struct {
	Login     string
	AuthSalt  []byte
	VaultSalt []byte
	KDFParams cryptoutil.KDFParams
}

// Session contains an authenticated user session returned by auth use cases.
type Session struct {
	User             domain.User
	AccessToken      string
	AccessExpiresAt  time.Time
	RefreshToken     string
	RefreshExpiresAt time.Time
}

// Service coordinates registration, login, refresh, and logout.
type Service struct {
	users         UserRepository
	refreshTokens RefreshTokenRepository
	tokens        TokenIssuer
	kdfParams     cryptoutil.KDFParams
	saltBytes     int
	newID         func() string
	now           func() time.Time
}

// NewService creates an auth service.
func NewService(cfg Config) (*Service, error) {
	if cfg.Users == nil {
		return nil, fmt.Errorf("user repository is required")
	}
	if cfg.RefreshTokens == nil {
		return nil, fmt.Errorf("refresh token repository is required")
	}
	if cfg.Tokens == nil {
		return nil, fmt.Errorf("token issuer is required")
	}

	params := cfg.KDFParams
	if params.Algorithm == "" {
		params = cryptoutil.DefaultKDFParams()
	}
	if err := params.Validate(); err != nil {
		return nil, err
	}

	saltBytes := cfg.SaltBytes
	if saltBytes == 0 {
		saltBytes = defaultSaltBytes
	}
	if saltBytes < 16 {
		return nil, fmt.Errorf("salt byte count must be at least 16")
	}

	newID := cfg.NewID
	if newID == nil {
		newID = func() string {
			return uuid.NewString()
		}
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}

	return &Service{
		users:         cfg.Users,
		refreshTokens: cfg.RefreshTokens,
		tokens:        cfg.Tokens,
		kdfParams:     params,
		saltBytes:     saltBytes,
		newID:         newID,
		now:           now,
	}, nil
}

// AuthParams returns KDF parameters and salts for an existing user.
func (s *Service) AuthParams(ctx context.Context, login string) (Params, error) {
	login = strings.TrimSpace(login)
	if login == "" {
		return Params{}, fmt.Errorf("%w: login is required", domain.ErrValidation)
	}

	user, err := s.users.FindByLogin(ctx, login)
	if err != nil {
		return Params{}, err
	}
	params, err := cryptoutil.ParseKDFParams(user.KDFParams)
	if err != nil {
		return Params{}, fmt.Errorf("parse user kdf params: %w", err)
	}

	return Params{
		Login:     user.Login,
		AuthSalt:  append([]byte(nil), user.AuthSalt...),
		VaultSalt: append([]byte(nil), user.VaultSalt...),
		KDFParams: params,
	}, nil
}

// Register creates a user and returns an initial authenticated session.
func (s *Service) Register(ctx context.Context, login string, authSecret []byte, clientID string) (Session, error) {
	login = strings.TrimSpace(login)
	clientID = strings.TrimSpace(clientID)
	if login == "" {
		return Session{}, fmt.Errorf("%w: login is required", domain.ErrValidation)
	}
	if err := validateAuthSecret(authSecret); err != nil {
		return Session{}, err
	}
	if clientID == "" {
		return Session{}, fmt.Errorf("%w: client id is required", domain.ErrValidation)
	}

	authSalt, err := cryptoutil.RandomBytes(s.saltBytes)
	if err != nil {
		return Session{}, err
	}
	vaultSalt, err := cryptoutil.RandomBytes(s.saltBytes)
	if err != nil {
		return Session{}, err
	}
	authSecretHash, err := cryptoutil.HashAuthSecret(authSecret, authSalt, s.kdfParams)
	if err != nil {
		return Session{}, err
	}
	kdfParams, err := cryptoutil.MarshalKDFParams(s.kdfParams)
	if err != nil {
		return Session{}, err
	}

	now := s.now().UTC()
	user := domain.User{
		ID:             s.newID(),
		Login:          login,
		AuthSalt:       authSalt,
		VaultSalt:      vaultSalt,
		AuthSecretHash: authSecretHash,
		KDFParams:      kdfParams,
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	if err = s.users.Create(ctx, user); err != nil {
		return Session{}, err
	}

	session, err := s.issueSession(ctx, user, clientID)
	if err != nil {
		return Session{}, err
	}
	return session, nil
}

// Login verifies credentials and returns an authenticated session.
func (s *Service) Login(ctx context.Context, login string, authSecret []byte, clientID string) (Session, error) {
	login = strings.TrimSpace(login)
	clientID = strings.TrimSpace(clientID)
	if login == "" {
		return Session{}, fmt.Errorf("%w: login is required", domain.ErrValidation)
	}
	if err := validateAuthSecret(authSecret); err != nil {
		return Session{}, err
	}
	if clientID == "" {
		return Session{}, fmt.Errorf("%w: client id is required", domain.ErrValidation)
	}

	user, err := s.users.FindByLogin(ctx, login)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return Session{}, ErrInvalidCredentials
		}
		return Session{}, err
	}
	params, err := cryptoutil.ParseKDFParams(user.KDFParams)
	if err != nil {
		return Session{}, fmt.Errorf("parse user kdf params: %w", err)
	}
	ok, err := cryptoutil.VerifyAuthSecret(authSecret, user.AuthSalt, params, user.AuthSecretHash)
	if err != nil {
		return Session{}, err
	}
	if !ok {
		return Session{}, ErrInvalidCredentials
	}

	return s.issueSession(ctx, user, clientID)
}

// Refresh rotates a refresh token and returns a new authenticated session.
func (s *Service) Refresh(ctx context.Context, refreshToken string) (Session, error) {
	refreshToken = strings.TrimSpace(refreshToken)
	if refreshToken == "" {
		return Session{}, ErrInvalidRefreshToken
	}

	storedToken, err := s.refreshTokens.FindByHash(ctx, tokens.HashRefreshToken(refreshToken))
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return Session{}, ErrInvalidRefreshToken
		}
		return Session{}, err
	}
	if storedToken.RevokedAt != nil || !storedToken.ExpiresAt.After(s.now()) {
		return Session{}, ErrInvalidRefreshToken
	}

	user, err := s.users.FindByID(ctx, storedToken.UserID)
	if err != nil {
		return Session{}, err
	}

	revokedAt := s.now().UTC()
	if err = s.refreshTokens.Revoke(ctx, storedToken.ID, revokedAt); err != nil {
		return Session{}, err
	}

	return s.issueSession(ctx, user, storedToken.ClientID)
}

// Logout revokes a refresh token.
func (s *Service) Logout(ctx context.Context, refreshToken string) error {
	refreshToken = strings.TrimSpace(refreshToken)
	if refreshToken == "" {
		return ErrInvalidRefreshToken
	}

	storedToken, err := s.refreshTokens.FindByHash(ctx, tokens.HashRefreshToken(refreshToken))
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return ErrInvalidRefreshToken
		}
		return err
	}
	if storedToken.RevokedAt != nil {
		return ErrInvalidRefreshToken
	}

	return s.refreshTokens.Revoke(ctx, storedToken.ID, s.now().UTC())
}

func (s *Service) issueSession(ctx context.Context, user domain.User, clientID string) (Session, error) {
	pair, err := s.tokens.IssuePair(user.ID, clientID)
	if err != nil {
		return Session{}, err
	}

	token := domain.RefreshToken{
		ID:        s.newID(),
		UserID:    user.ID,
		TokenHash: pair.RefreshTokenHash,
		ClientID:  clientID,
		ExpiresAt: pair.RefreshExpiresAt,
		CreatedAt: pair.RefreshTokenIssued,
	}
	if err = s.refreshTokens.Create(ctx, token); err != nil {
		return Session{}, err
	}

	return Session{
		User:             user.Clone(),
		AccessToken:      pair.AccessToken,
		AccessExpiresAt:  pair.AccessExpiresAt,
		RefreshToken:     pair.RefreshToken,
		RefreshExpiresAt: pair.RefreshExpiresAt,
	}, nil
}

func validateAuthSecret(authSecret []byte) error {
	if len(authSecret) < minAuthSecretByteCount {
		return fmt.Errorf("%w: auth secret must be at least %d bytes", domain.ErrValidation, minAuthSecretByteCount)
	}
	return nil
}
