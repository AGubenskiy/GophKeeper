package tokens

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/AGubenskiy/GophKeeper/internal/cryptoutil"
	"github.com/golang-jwt/jwt/v5"
)

const (
	defaultIssuer     = "gophkeeper"
	refreshTokenBytes = 32
)

// Config contains token service settings.
type Config struct {
	Issuer       string
	AccessSecret []byte
	AccessTTL    time.Duration
	RefreshTTL   time.Duration
	Now          func() time.Time
}

// Pair contains newly issued access and refresh tokens.
type Pair struct {
	AccessToken        string
	AccessExpiresAt    time.Time
	RefreshToken       string
	RefreshTokenHash   []byte
	RefreshExpiresAt   time.Time
	RefreshTokenIssued time.Time
}

// Principal describes the authenticated user and client encoded in an access token.
type Principal struct {
	UserID   string
	ClientID string
	TokenID  string
	Issuer   string
	Expires  time.Time
}

// Service issues and verifies authentication tokens.
type Service struct {
	issuer       string
	accessSecret []byte
	accessTTL    time.Duration
	refreshTTL   time.Duration
	now          func() time.Time
}

// NewService creates a token service.
func NewService(cfg Config) (*Service, error) {
	issuer := strings.TrimSpace(cfg.Issuer)
	if issuer == "" {
		issuer = defaultIssuer
	}
	if len(cfg.AccessSecret) < 32 {
		return nil, fmt.Errorf("access token secret must be at least 32 bytes")
	}
	if cfg.AccessTTL <= 0 {
		return nil, fmt.Errorf("access token ttl must be positive")
	}
	if cfg.RefreshTTL <= 0 {
		return nil, fmt.Errorf("refresh token ttl must be positive")
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}

	return &Service{
		issuer:       issuer,
		accessSecret: append([]byte(nil), cfg.AccessSecret...),
		accessTTL:    cfg.AccessTTL,
		refreshTTL:   cfg.RefreshTTL,
		now:          now,
	}, nil
}

// IssuePair issues a signed access token and a random refresh token for a client session.
func (s *Service) IssuePair(userID, clientID string) (Pair, error) {
	if strings.TrimSpace(userID) == "" {
		return Pair{}, fmt.Errorf("user id is required")
	}
	if strings.TrimSpace(clientID) == "" {
		return Pair{}, fmt.Errorf("client id is required")
	}

	issuedAt := s.now().UTC()
	accessExpiresAt := issuedAt.Add(s.accessTTL)
	refreshExpiresAt := issuedAt.Add(s.refreshTTL)

	tokenIDBytes, err := cryptoutil.RandomBytes(16)
	if err != nil {
		return Pair{}, err
	}
	tokenID := base64.RawURLEncoding.EncodeToString(tokenIDBytes)

	claims := accessClaims{
		UserID:   userID,
		ClientID: clientID,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.issuer,
			Subject:   userID,
			ID:        tokenID,
			IssuedAt:  jwt.NewNumericDate(issuedAt),
			ExpiresAt: jwt.NewNumericDate(accessExpiresAt),
		},
	}

	accessToken, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(s.accessSecret)
	if err != nil {
		return Pair{}, fmt.Errorf("sign access token: %w", err)
	}

	refreshBytes, err := cryptoutil.RandomBytes(refreshTokenBytes)
	if err != nil {
		return Pair{}, err
	}
	refreshToken := base64.RawURLEncoding.EncodeToString(refreshBytes)

	return Pair{
		AccessToken:        accessToken,
		AccessExpiresAt:    accessExpiresAt,
		RefreshToken:       refreshToken,
		RefreshTokenHash:   HashRefreshToken(refreshToken),
		RefreshExpiresAt:   refreshExpiresAt,
		RefreshTokenIssued: issuedAt,
	}, nil
}

// VerifyAccess verifies an access token and returns its principal.
func (s *Service) VerifyAccess(tokenText string) (Principal, error) {
	tokenText = strings.TrimSpace(tokenText)
	if tokenText == "" {
		return Principal{}, fmt.Errorf("access token is required")
	}

	claims := accessClaims{}
	token, err := jwt.ParseWithClaims(
		tokenText,
		&claims,
		func(token *jwt.Token) (any, error) {
			if token.Method != jwt.SigningMethodHS256 {
				return nil, fmt.Errorf("unexpected signing method %s", token.Method.Alg())
			}
			return s.accessSecret, nil
		},
		jwt.WithIssuer(s.issuer),
		jwt.WithExpirationRequired(),
		jwt.WithTimeFunc(s.now),
	)
	if err != nil {
		return Principal{}, fmt.Errorf("verify access token: %w", err)
	}
	if !token.Valid {
		return Principal{}, errors.New("access token is invalid")
	}
	if strings.TrimSpace(claims.UserID) == "" || strings.TrimSpace(claims.ClientID) == "" {
		return Principal{}, errors.New("access token is missing principal claims")
	}

	return Principal{
		UserID:   claims.UserID,
		ClientID: claims.ClientID,
		TokenID:  claims.ID,
		Issuer:   claims.Issuer,
		Expires:  claims.ExpiresAt.Time,
	}, nil
}

// HashRefreshToken returns the server-side storage hash for a refresh token.
func HashRefreshToken(refreshToken string) []byte {
	sum := sha256.Sum256([]byte(strings.TrimSpace(refreshToken)))
	return sum[:]
}

type accessClaims struct {
	UserID   string `json:"uid"`
	ClientID string `json:"cid"`
	jwt.RegisteredClaims
}
