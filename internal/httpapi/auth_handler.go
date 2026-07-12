package httpapi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/AGubenskiy/GophKeeper/internal/auth"
	"github.com/AGubenskiy/GophKeeper/internal/cryptoutil"
)

const maxAuthJSONBodyBytes = 1 << 20
const maxSyncJSONBodyBytes = 128 << 20

// AuthService is the auth use-case surface required by HTTP handlers.
type AuthService interface {
	AuthParams(ctx context.Context, login string) (auth.Params, error)
	Register(ctx context.Context, login string, authSecret []byte, clientID string) (auth.Session, error)
	Login(ctx context.Context, login string, authSecret []byte, clientID string) (auth.Session, error)
	Refresh(ctx context.Context, refreshToken string) (auth.Session, error)
	Logout(ctx context.Context, refreshToken string) error
}

// AuthHandler exposes authentication routes.
type AuthHandler struct {
	service AuthService
}

// NewAuthHandler creates an auth HTTP handler.
func NewAuthHandler(service AuthService) *AuthHandler {
	return &AuthHandler{service: service}
}

// RegisterRoutes registers auth endpoints on mux.
func (h *AuthHandler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/v1/auth/params", h.handleParams)
	mux.HandleFunc("/api/v1/auth/register", h.handleRegister)
	mux.HandleFunc("/api/v1/auth/login", h.handleLogin)
	mux.HandleFunc("/api/v1/auth/refresh", h.handleRefresh)
	mux.HandleFunc("/api/v1/auth/logout", h.handleLogout)
}

func (h *AuthHandler) handleParams(w http.ResponseWriter, r *http.Request) {
	if !methodAllowed(w, r, http.MethodGet) || !h.available(w, r) {
		return
	}

	params, err := h.service.AuthParams(r.Context(), r.URL.Query().Get("login"))
	if err != nil {
		writeMappedError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, authParamsResponseFrom(params))
}

func (h *AuthHandler) handleRegister(w http.ResponseWriter, r *http.Request) {
	if !methodAllowed(w, r, http.MethodPost) || !h.available(w, r) {
		return
	}

	var request credentialsRequest
	if !decodeJSONRequest(w, r, &request) {
		return
	}
	authSecret, ok := decodeAuthSecret(w, r, request.AuthSecret)
	if !ok {
		return
	}

	session, err := h.service.Register(r.Context(), request.Login, authSecret, request.ClientID)
	cryptoutil.Zero(authSecret)
	if err != nil {
		writeMappedError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, sessionResponseFrom(session, true))
}

func (h *AuthHandler) handleLogin(w http.ResponseWriter, r *http.Request) {
	if !methodAllowed(w, r, http.MethodPost) || !h.available(w, r) {
		return
	}

	var request credentialsRequest
	if !decodeJSONRequest(w, r, &request) {
		return
	}
	authSecret, ok := decodeAuthSecret(w, r, request.AuthSecret)
	if !ok {
		return
	}

	session, err := h.service.Login(r.Context(), request.Login, authSecret, request.ClientID)
	cryptoutil.Zero(authSecret)
	if err != nil {
		writeMappedError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, sessionResponseFrom(session, true))
}

func (h *AuthHandler) handleRefresh(w http.ResponseWriter, r *http.Request) {
	if !methodAllowed(w, r, http.MethodPost) || !h.available(w, r) {
		return
	}

	var request refreshRequest
	if !decodeJSONRequest(w, r, &request) {
		return
	}

	session, err := h.service.Refresh(r.Context(), request.RefreshToken)
	if err != nil {
		writeMappedError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, sessionResponseFrom(session, false))
}

func (h *AuthHandler) handleLogout(w http.ResponseWriter, r *http.Request) {
	if !methodAllowed(w, r, http.MethodPost) || !h.available(w, r) {
		return
	}

	var request refreshRequest
	if !decodeJSONRequest(w, r, &request) {
		return
	}

	if err := h.service.Logout(r.Context(), request.RefreshToken); err != nil {
		writeMappedError(w, r, err)
		return
	}
	writeNoContent(w)
}

func (h *AuthHandler) available(w http.ResponseWriter, r *http.Request) bool {
	if h.service != nil {
		return true
	}
	writeAPIError(w, r, http.StatusServiceUnavailable, errorAuthUnavailable, "auth service is not configured")
	return false
}

func decodeJSONRequest(w http.ResponseWriter, r *http.Request, target any) bool {
	return decodeJSONRequestWithLimit(w, r, target, maxAuthJSONBodyBytes)
}

func decodeJSONRequestWithLimit(w http.ResponseWriter, r *http.Request, target any, maxBodyBytes int64) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		writeAPIError(w, r, http.StatusBadRequest, errorValidation, "invalid JSON request body")
		return false
	}
	if err := decoder.Decode(&struct{}{}); err == nil {
		writeAPIError(w, r, http.StatusBadRequest, errorValidation, "request body must contain a single JSON object")
		return false
	} else if err != io.EOF {
		writeAPIError(w, r, http.StatusBadRequest, errorValidation, "invalid JSON request body")
		return false
	}
	return true
}

func decodeAuthSecret(w http.ResponseWriter, r *http.Request, encoded string) ([]byte, bool) {
	encoded = strings.TrimSpace(encoded)
	if encoded == "" {
		writeAPIError(w, r, http.StatusBadRequest, errorValidation, "auth_secret is required")
		return nil, false
	}

	secret, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		secret, err = base64.RawStdEncoding.DecodeString(encoded)
	}
	if err != nil {
		writeAPIError(w, r, http.StatusBadRequest, errorValidation, "auth_secret must be base64 encoded")
		return nil, false
	}
	return secret, true
}

type credentialsRequest struct {
	Login      string `json:"login"`
	AuthSecret string `json:"auth_secret"`
	ClientID   string `json:"client_id"`
}

type refreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

type authParamsResponse struct {
	Login     string               `json:"login"`
	AuthSalt  string               `json:"auth_salt"`
	VaultSalt string               `json:"vault_salt"`
	KDFParams cryptoutil.KDFParams `json:"kdf_params"`
}

type sessionResponse struct {
	UserID           string                `json:"user_id"`
	Login            string                `json:"login"`
	AccessToken      string                `json:"access_token"`
	AccessExpiresAt  string                `json:"access_expires_at"`
	RefreshToken     string                `json:"refresh_token"`
	RefreshExpiresAt string                `json:"refresh_expires_at"`
	AuthSalt         string                `json:"auth_salt,omitempty"`
	VaultSalt        string                `json:"vault_salt,omitempty"`
	KDFParams        *cryptoutil.KDFParams `json:"kdf_params,omitempty"`
}

func authParamsResponseFrom(params auth.Params) authParamsResponse {
	return authParamsResponse{
		Login:     params.Login,
		AuthSalt:  base64.StdEncoding.EncodeToString(params.AuthSalt),
		VaultSalt: base64.StdEncoding.EncodeToString(params.VaultSalt),
		KDFParams: params.KDFParams,
	}
}

func sessionResponseFrom(session auth.Session, includeParams bool) sessionResponse {
	response := sessionResponse{
		UserID:           session.User.ID,
		Login:            session.User.Login,
		AccessToken:      session.AccessToken,
		AccessExpiresAt:  session.AccessExpiresAt.Format(time.RFC3339),
		RefreshToken:     session.RefreshToken,
		RefreshExpiresAt: session.RefreshExpiresAt.Format(time.RFC3339),
	}
	if includeParams {
		params, err := cryptoutil.ParseKDFParams(session.User.KDFParams)
		if err == nil {
			response.KDFParams = &params
		}
		response.AuthSalt = base64.StdEncoding.EncodeToString(session.User.AuthSalt)
		response.VaultSalt = base64.StdEncoding.EncodeToString(session.User.VaultSalt)
	}
	return response
}
