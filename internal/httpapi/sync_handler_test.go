package httpapi

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/AGubenskiy/GophKeeper/internal/domain"
	"github.com/AGubenskiy/GophKeeper/internal/syncsvc"
	"github.com/AGubenskiy/GophKeeper/internal/tokens"
)

func TestSyncHandlerChanges(t *testing.T) {
	service := &fakeSyncService{
		changes: syncsvc.Changes{
			Items:           []domain.VaultItem{testSyncItem("item-1", 3)},
			CurrentRevision: 3,
		},
	}
	mux := http.NewServeMux()
	NewSyncHandler(service, fakeVerifier{principal: tokens.Principal{UserID: "user-1", ClientID: "client-1"}}).RegisterRoutes(mux)

	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/v1/sync/changes?since_revision=2", nil)
	request.Header.Set("Authorization", "Bearer access-token")
	mux.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", response.Code, http.StatusOK, response.Body.String())
	}
	if service.pullUserID != "user-1" || service.pullSince != 2 {
		t.Fatalf("pull args = %q/%d, want user-1/2", service.pullUserID, service.pullSince)
	}

	var body changesResponse
	decodeResponse(t, response, &body)
	if body.CurrentRevision != 3 || body.Items[0].EncryptedPayload != base64.StdEncoding.EncodeToString([]byte("ciphertext")) {
		t.Fatalf("changes response = %+v, want encoded item", body)
	}
}

func TestSyncHandlerPush(t *testing.T) {
	service := &fakeSyncService{
		pushResult: syncsvc.PushResult{
			Applied:         []domain.VaultItem{testSyncItem("item-1", 4)},
			CurrentRevision: 4,
		},
	}
	mux := http.NewServeMux()
	NewSyncHandler(service, fakeVerifier{principal: tokens.Principal{UserID: "user-1", ClientID: "client-1"}}).RegisterRoutes(mux)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/v1/sync/push", jsonBody(t, pushRequest{
		Items: []pushItemRequest{
			{
				ID:               "item-1",
				BaseRevision:     3,
				EncryptedPayload: base64.StdEncoding.EncodeToString([]byte("ciphertext")),
				PayloadNonce:     base64.StdEncoding.EncodeToString([]byte("nonce")),
				PayloadVersion:   1,
			},
		},
	}))
	request.Header.Set(headerContentType, contentTypeApplicationJSON)
	request.Header.Set("Authorization", "Bearer access-token")
	mux.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", recorder.Code, http.StatusOK, recorder.Body.String())
	}
	if service.pushUserID != "user-1" || len(service.mutations) != 1 || string(service.mutations[0].EncryptedPayload) != "ciphertext" {
		t.Fatalf("push captured = %q %+v, want decoded mutation", service.pushUserID, service.mutations)
	}
}

func TestSyncHandlerUnavailableAndInvalidRequest(t *testing.T) {
	mux := http.NewServeMux()
	NewSyncHandler(nil, nil).RegisterRoutes(mux)

	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/v1/sync/changes?since_revision=0", nil)
	mux.ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusServiceUnavailable)
	}

	mux = http.NewServeMux()
	NewSyncHandler(&fakeSyncService{}, fakeVerifier{principal: tokens.Principal{UserID: "user-1"}}).RegisterRoutes(mux)
	response = httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodPost, "/api/v1/sync/push", jsonBody(t, pushRequest{
		Items: []pushItemRequest{{ID: "item-1", EncryptedPayload: "not-base64", PayloadNonce: "bm9uY2U=", PayloadVersion: 1}},
	}))
	request.Header.Set(headerContentType, contentTypeApplicationJSON)
	request.Header.Set("Authorization", "Bearer access-token")
	mux.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusBadRequest)
	}
}

func jsonBody(t *testing.T, value any) *bytes.Buffer {
	t.Helper()
	var body bytes.Buffer
	if err := json.NewEncoder(&body).Encode(value); err != nil {
		t.Fatalf("encode json body: %v", err)
	}
	return &body
}

func testSyncItem(id string, revision int64) domain.VaultItem {
	now := time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)
	return domain.VaultItem{
		ID:               id,
		UserID:           "user-1",
		ServerRevision:   revision,
		EncryptedPayload: []byte("ciphertext"),
		PayloadNonce:     []byte("nonce"),
		PayloadVersion:   1,
		CreatedAt:        now,
		UpdatedAt:        now,
	}
}

type fakeSyncService struct {
	changes    syncsvc.Changes
	pushResult syncsvc.PushResult
	pullUserID string
	pullSince  int64
	pushUserID string
	mutations  []syncsvc.Mutation
}

func (f *fakeSyncService) Pull(_ context.Context, userID string, sinceRevision int64, limit int) (syncsvc.Changes, error) {
	f.pullUserID = userID
	f.pullSince = sinceRevision
	return f.changes, nil
}

func (f *fakeSyncService) Push(_ context.Context, userID string, mutations []syncsvc.Mutation) (syncsvc.PushResult, error) {
	f.pushUserID = userID
	f.mutations = append([]syncsvc.Mutation(nil), mutations...)
	return f.pushResult, nil
}
