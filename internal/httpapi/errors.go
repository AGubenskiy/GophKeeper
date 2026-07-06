package httpapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/AGubenskiy/GophKeeper/internal/auth"
	"github.com/AGubenskiy/GophKeeper/internal/domain"
)

const (
	errorAlreadyExists         = "already_exists"
	errorAuthUnavailable       = "auth_unavailable"
	errorInternal              = "internal"
	errorInvalidCredentials    = "invalid_credentials"
	errorInvalidRefreshToken   = "invalid_refresh_token"
	errorMethodNotAllowed      = "method_not_allowed"
	errorNotFound              = "not_found"
	errorConflict              = "conflict"
	errorSyncUnavailable       = "sync_unavailable"
	errorUnauthorized          = "unauthorized"
	errorValidation            = "validation_error"
	headerRequestID            = "X-Request-ID"
	headerContentType          = "Content-Type"
	contentTypeApplicationJSON = "application/json"
)

// ErrorResponse is the stable API error envelope.
type ErrorResponse struct {
	Error ErrorBody `json:"error"`
}

// ErrorBody describes one API error.
type ErrorBody struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	RequestID string `json:"request_id"`
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set(headerContentType, contentTypeApplicationJSON)
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(value); err != nil {
		panic(err)
	}
}

func writeNoContent(w http.ResponseWriter) {
	w.WriteHeader(http.StatusNoContent)
}

func writeAPIError(w http.ResponseWriter, r *http.Request, status int, code, message string) {
	writeJSON(w, status, ErrorResponse{
		Error: ErrorBody{
			Code:      code,
			Message:   message,
			RequestID: requestID(r),
		},
	})
}

func writeMappedError(w http.ResponseWriter, r *http.Request, err error) {
	status, code, message := mapError(err)
	writeAPIError(w, r, status, code, message)
}

func mapError(err error) (int, string, string) {
	switch {
	case errors.Is(err, auth.ErrInvalidCredentials):
		return http.StatusUnauthorized, errorInvalidCredentials, "invalid credentials"
	case errors.Is(err, auth.ErrInvalidRefreshToken):
		return http.StatusUnauthorized, errorInvalidRefreshToken, "invalid refresh token"
	case errors.Is(err, domain.ErrAlreadyExists):
		return http.StatusConflict, errorAlreadyExists, "resource already exists"
	case errors.Is(err, domain.ErrNotFound):
		return http.StatusNotFound, errorNotFound, "resource not found"
	case errors.Is(err, domain.ErrConflict):
		return http.StatusConflict, errorConflict, "resource conflict"
	case errors.Is(err, domain.ErrValidation):
		return http.StatusBadRequest, errorValidation, err.Error()
	default:
		return http.StatusInternalServerError, errorInternal, "internal server error"
	}
}

func methodAllowed(w http.ResponseWriter, r *http.Request, method string) bool {
	if r.Method == method {
		return true
	}
	w.Header().Set("Allow", method)
	writeAPIError(
		w,
		r,
		http.StatusMethodNotAllowed,
		errorMethodNotAllowed,
		fmt.Sprintf("method %s is not allowed", r.Method),
	)
	return false
}

func requestID(r *http.Request) string {
	if r == nil {
		return ""
	}
	if id, ok := RequestIDFromContext(r.Context()); ok {
		return id
	}
	return r.Header.Get(headerRequestID)
}
