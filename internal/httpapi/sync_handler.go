package httpapi

import (
	"context"
	"encoding/base64"
	"net/http"
	"strconv"
	"time"

	"github.com/AGubenskiy/GophKeeper/internal/domain"
	"github.com/AGubenskiy/GophKeeper/internal/syncsvc"
)

// SyncService is the sync use-case surface required by HTTP handlers.
type SyncService interface {
	Pull(ctx context.Context, userID string, sinceRevision int64, limit int) (syncsvc.Changes, error)
	Push(ctx context.Context, userID string, mutations []syncsvc.Mutation) (syncsvc.PushResult, error)
}

// SyncHandler exposes encrypted vault synchronization routes.
type SyncHandler struct {
	service  SyncService
	verifier TokenVerifier
}

// NewSyncHandler creates a sync HTTP handler.
func NewSyncHandler(service SyncService, verifier TokenVerifier) *SyncHandler {
	return &SyncHandler{service: service, verifier: verifier}
}

// RegisterRoutes registers sync endpoints on mux.
func (h *SyncHandler) RegisterRoutes(mux *http.ServeMux) {
	mux.Handle("/api/v1/sync/changes", h.protected(http.HandlerFunc(h.handleChanges)))
	mux.Handle("/api/v1/sync/push", h.protected(http.HandlerFunc(h.handlePush)))
}

func (h *SyncHandler) protected(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !h.available(w, r) {
			return
		}
		AuthMiddleware(h.verifier)(next).ServeHTTP(w, r)
	})
}

func (h *SyncHandler) handleChanges(w http.ResponseWriter, r *http.Request) {
	if !methodAllowed(w, r, http.MethodGet) {
		return
	}
	principal, ok := PrincipalFromContext(r.Context())
	if !ok {
		writeAPIError(w, r, http.StatusUnauthorized, errorUnauthorized, "authenticated principal is required")
		return
	}

	since, ok := parseNonNegativeQueryInt(w, r, "since_revision")
	if !ok {
		return
	}
	limit, ok := parseOptionalQueryInt(w, r, "limit")
	if !ok {
		return
	}

	changes, err := h.service.Pull(r.Context(), principal.UserID, since, int(limit))
	if err != nil {
		writeMappedError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, changesResponseFrom(changes))
}

func (h *SyncHandler) handlePush(w http.ResponseWriter, r *http.Request) {
	if !methodAllowed(w, r, http.MethodPost) {
		return
	}
	principal, ok := PrincipalFromContext(r.Context())
	if !ok {
		writeAPIError(w, r, http.StatusUnauthorized, errorUnauthorized, "authenticated principal is required")
		return
	}

	var request pushRequest
	if !decodeJSONRequest(w, r, &request) {
		return
	}
	mutations, ok := decodeMutations(w, r, request.Items)
	if !ok {
		return
	}

	result, err := h.service.Push(r.Context(), principal.UserID, mutations)
	if err != nil {
		writeMappedError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, pushResponseFrom(result))
}

func (h *SyncHandler) available(w http.ResponseWriter, r *http.Request) bool {
	if h.service != nil && h.verifier != nil {
		return true
	}
	writeAPIError(w, r, http.StatusServiceUnavailable, errorSyncUnavailable, "sync service is not configured")
	return false
}

func parseNonNegativeQueryInt(w http.ResponseWriter, r *http.Request, name string) (int64, bool) {
	raw := r.URL.Query().Get(name)
	if raw == "" {
		writeAPIError(w, r, http.StatusBadRequest, errorValidation, name+" is required")
		return 0, false
	}
	value, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || value < 0 {
		writeAPIError(w, r, http.StatusBadRequest, errorValidation, name+" must be a non-negative integer")
		return 0, false
	}
	return value, true
}

func parseOptionalQueryInt(w http.ResponseWriter, r *http.Request, name string) (int64, bool) {
	raw := r.URL.Query().Get(name)
	if raw == "" {
		return 0, true
	}
	value, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || value < 0 {
		writeAPIError(w, r, http.StatusBadRequest, errorValidation, name+" must be a non-negative integer")
		return 0, false
	}
	return value, true
}

func decodeMutations(w http.ResponseWriter, r *http.Request, items []pushItemRequest) ([]syncsvc.Mutation, bool) {
	mutations := make([]syncsvc.Mutation, 0, len(items))
	for _, item := range items {
		payload, ok := decodeBase64Field(w, r, "encrypted_payload", item.EncryptedPayload)
		if !ok {
			return nil, false
		}
		nonce, ok := decodeBase64Field(w, r, "payload_nonce", item.PayloadNonce)
		if !ok {
			return nil, false
		}
		mutations = append(mutations, syncsvc.Mutation{
			ID:               item.ID,
			BaseRevision:     item.BaseRevision,
			EncryptedPayload: payload,
			PayloadNonce:     nonce,
			PayloadVersion:   item.PayloadVersion,
			DeletedAt:        item.DeletedAt,
		})
	}
	return mutations, true
}

func decodeBase64Field(w http.ResponseWriter, r *http.Request, name, value string) ([]byte, bool) {
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		writeAPIError(w, r, http.StatusBadRequest, errorValidation, name+" must be base64 encoded")
		return nil, false
	}
	return decoded, true
}

type pushRequest struct {
	Items []pushItemRequest `json:"items"`
}

type pushItemRequest struct {
	ID               string     `json:"id"`
	BaseRevision     int64      `json:"base_revision"`
	EncryptedPayload string     `json:"encrypted_payload"`
	PayloadNonce     string     `json:"payload_nonce"`
	PayloadVersion   int16      `json:"payload_version"`
	DeletedAt        *time.Time `json:"deleted_at,omitempty"`
}

type changesResponse struct {
	Items           []syncItemResponse `json:"items"`
	CurrentRevision int64              `json:"current_revision"`
}

type pushResponse struct {
	Applied         []syncItemResponse     `json:"applied"`
	Conflicts       []syncConflictResponse `json:"conflicts"`
	CurrentRevision int64                  `json:"current_revision"`
}

type syncItemResponse struct {
	ID               string     `json:"id"`
	ServerRevision   int64      `json:"server_revision"`
	EncryptedPayload string     `json:"encrypted_payload"`
	PayloadNonce     string     `json:"payload_nonce"`
	PayloadVersion   int16      `json:"payload_version"`
	DeletedAt        *time.Time `json:"deleted_at,omitempty"`
	UpdatedAt        time.Time  `json:"updated_at"`
}

type syncConflictResponse struct {
	ID             string            `json:"id"`
	BaseRevision   int64             `json:"base_revision"`
	ServerRevision int64             `json:"server_revision"`
	Reason         string            `json:"reason"`
	Remote         *syncItemResponse `json:"remote,omitempty"`
}

func changesResponseFrom(changes syncsvc.Changes) changesResponse {
	return changesResponse{
		Items:           syncItemsResponseFrom(changes.Items),
		CurrentRevision: changes.CurrentRevision,
	}
}

func pushResponseFrom(result syncsvc.PushResult) pushResponse {
	conflicts := make([]syncConflictResponse, 0, len(result.Conflicts))
	for _, conflict := range result.Conflicts {
		var remote *syncItemResponse
		if conflict.Remote != nil {
			encoded := syncItemResponseFrom(*conflict.Remote)
			remote = &encoded
		}
		conflicts = append(conflicts, syncConflictResponse{
			ID:             conflict.ID,
			BaseRevision:   conflict.BaseRevision,
			ServerRevision: conflict.ServerRevision,
			Reason:         conflict.Reason,
			Remote:         remote,
		})
	}
	return pushResponse{
		Applied:         syncItemsResponseFrom(result.Applied),
		Conflicts:       conflicts,
		CurrentRevision: result.CurrentRevision,
	}
}

func syncItemsResponseFrom(items []domain.VaultItem) []syncItemResponse {
	out := make([]syncItemResponse, 0, len(items))
	for _, item := range items {
		out = append(out, syncItemResponseFrom(item))
	}
	return out
}

func syncItemResponseFrom(item domain.VaultItem) syncItemResponse {
	return syncItemResponse{
		ID:               item.ID,
		ServerRevision:   item.ServerRevision,
		EncryptedPayload: base64.StdEncoding.EncodeToString(item.EncryptedPayload),
		PayloadNonce:     base64.StdEncoding.EncodeToString(item.PayloadNonce),
		PayloadVersion:   item.PayloadVersion,
		DeletedAt:        item.DeletedAt,
		UpdatedAt:        item.UpdatedAt,
	}
}
