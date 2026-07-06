package clientapi

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/AGubenskiy/GophKeeper/internal/cryptoutil"
)

const maxResponseBytes = 4 << 20

// Error describes an error returned by the GophKeeper HTTP API.
type Error struct {
	StatusCode int
	Code       string
	Message    string
	RequestID  string
}

// Error formats the API error for user-facing command output and logs.
func (e *Error) Error() string {
	if e == nil {
		return ""
	}
	if e.Code == "" {
		return fmt.Sprintf("api error: status %d", e.StatusCode)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// Client calls the GophKeeper HTTP API.
type Client struct {
	baseURL    *url.URL
	httpClient *http.Client
}

// New creates a client for serverURL.
func New(serverURL string, httpClient *http.Client) (*Client, error) {
	trimmed := strings.TrimSpace(serverURL)
	if trimmed == "" {
		return nil, errors.New("server url is required")
	}

	parsed, err := url.Parse(trimmed)
	if err != nil {
		return nil, fmt.Errorf("parse server url: %w", err)
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return nil, errors.New("server url must include scheme and host")
	}
	parsed.Path = strings.TrimRight(parsed.Path, "/")

	if httpClient == nil {
		httpClient = &http.Client{Timeout: 10 * time.Second}
	}

	return &Client{
		baseURL:    parsed,
		httpClient: httpClient,
	}, nil
}

// AuthParams fetches KDF parameters and salts for login.
func (c *Client) AuthParams(ctx context.Context, login string) (AuthParams, error) {
	endpoint := c.endpoint("/api/v1/auth/params")
	query := endpoint.Query()
	query.Set("login", login)
	endpoint.RawQuery = query.Encode()

	var response AuthParams
	if err := c.do(ctx, http.MethodGet, endpoint.String(), nil, http.StatusOK, &response); err != nil {
		return AuthParams{}, err
	}
	return response, nil
}

// Register creates a user and session.
func (c *Client) Register(ctx context.Context, request CredentialsRequest) (Session, error) {
	var response Session
	if err := c.do(ctx, http.MethodPost, c.endpoint("/api/v1/auth/register").String(), request, http.StatusCreated, &response); err != nil {
		return Session{}, err
	}
	return response, nil
}

// Login creates a session for an existing user.
func (c *Client) Login(ctx context.Context, request CredentialsRequest) (Session, error) {
	var response Session
	if err := c.do(ctx, http.MethodPost, c.endpoint("/api/v1/auth/login").String(), request, http.StatusOK, &response); err != nil {
		return Session{}, err
	}
	return response, nil
}

// Refresh rotates a refresh token and returns a new session.
func (c *Client) Refresh(ctx context.Context, refreshToken string) (Session, error) {
	var response Session
	if err := c.do(ctx, http.MethodPost, c.endpoint("/api/v1/auth/refresh").String(), refreshRequest{RefreshToken: refreshToken}, http.StatusOK, &response); err != nil {
		return Session{}, err
	}
	return response, nil
}

// Logout revokes a refresh token.
func (c *Client) Logout(ctx context.Context, refreshToken string) error {
	return c.do(ctx, http.MethodPost, c.endpoint("/api/v1/auth/logout").String(), refreshRequest{RefreshToken: refreshToken}, http.StatusNoContent, nil)
}

func (c *Client) do(ctx context.Context, method, endpoint string, requestBody any, expectedStatus int, responseBody any) error {
	return c.doWithToken(ctx, method, endpoint, "", requestBody, expectedStatus, responseBody)
}

func (c *Client) doWithToken(ctx context.Context, method, endpoint, accessToken string, requestBody any, expectedStatus int, responseBody any) error {
	var body io.Reader
	if requestBody != nil {
		var buffer bytes.Buffer
		if err := json.NewEncoder(&buffer).Encode(requestBody); err != nil {
			return fmt.Errorf("encode request: %w", err)
		}
		body = &buffer
	}

	request, err := http.NewRequestWithContext(ctx, method, endpoint, body)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	if requestBody != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if strings.TrimSpace(accessToken) != "" {
		request.Header.Set("Authorization", "Bearer "+strings.TrimSpace(accessToken))
	}

	response, err := c.httpClient.Do(request)
	if err != nil {
		return fmt.Errorf("send request: %w", err)
	}
	defer func() {
		_ = response.Body.Close()
	}()

	if response.StatusCode != expectedStatus {
		return decodeAPIError(response)
	}
	if responseBody == nil {
		return nil
	}

	limited := io.LimitReader(response.Body, maxResponseBytes)
	decoder := json.NewDecoder(limited)
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(responseBody); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	return nil
}

func decodeAPIError(response *http.Response) error {
	var body struct {
		Error struct {
			Code      string `json:"code"`
			Message   string `json:"message"`
			RequestID string `json:"request_id"`
		} `json:"error"`
	}

	data, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes))
	if err == nil && len(data) > 0 {
		_ = json.Unmarshal(data, &body)
	}

	if body.Error.Message == "" {
		body.Error.Message = http.StatusText(response.StatusCode)
	}
	return &Error{
		StatusCode: response.StatusCode,
		Code:       body.Error.Code,
		Message:    body.Error.Message,
		RequestID:  body.Error.RequestID,
	}
}

func (c *Client) endpoint(path string) *url.URL {
	endpoint := *c.baseURL
	endpoint.Path = strings.TrimRight(c.baseURL.Path, "/") + path
	return &endpoint
}

// CredentialsRequest contains credentials sent to register/login endpoints.
type CredentialsRequest struct {
	Login      string `json:"login"`
	AuthSecret string `json:"auth_secret"`
	ClientID   string `json:"client_id"`
}

// NewCredentialsRequest encodes authSecret for an auth request.
func NewCredentialsRequest(login string, authSecret []byte, clientID string) CredentialsRequest {
	return CredentialsRequest{
		Login:      login,
		AuthSecret: base64.StdEncoding.EncodeToString(authSecret),
		ClientID:   clientID,
	}
}

// AuthParams contains KDF parameters and salts for an account.
type AuthParams struct {
	Login     string               `json:"login"`
	AuthSalt  string               `json:"auth_salt"`
	VaultSalt string               `json:"vault_salt"`
	KDFParams cryptoutil.KDFParams `json:"kdf_params"`
}

// AuthSaltBytes decodes the auth salt.
func (p AuthParams) AuthSaltBytes() ([]byte, error) {
	return base64.StdEncoding.DecodeString(p.AuthSalt)
}

// VaultSaltBytes decodes the vault salt.
func (p AuthParams) VaultSaltBytes() ([]byte, error) {
	return base64.StdEncoding.DecodeString(p.VaultSalt)
}

// Session contains tokens and profile data returned by auth endpoints.
type Session struct {
	UserID           string                `json:"user_id"`
	Login            string                `json:"login"`
	AccessToken      string                `json:"access_token"`
	AccessExpiresAt  time.Time             `json:"access_expires_at"`
	RefreshToken     string                `json:"refresh_token"`
	RefreshExpiresAt time.Time             `json:"refresh_expires_at"`
	AuthSalt         string                `json:"auth_salt"`
	VaultSalt        string                `json:"vault_salt"`
	KDFParams        *cryptoutil.KDFParams `json:"kdf_params"`
}

// AuthSaltBytes decodes the auth salt.
func (s Session) AuthSaltBytes() ([]byte, error) {
	return base64.StdEncoding.DecodeString(s.AuthSalt)
}

// VaultSaltBytes decodes the vault salt.
func (s Session) VaultSaltBytes() ([]byte, error) {
	return base64.StdEncoding.DecodeString(s.VaultSalt)
}

type refreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}
