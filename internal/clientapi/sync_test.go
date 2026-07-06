package clientapi

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestClientPushAndPullChanges(t *testing.T) {
	updatedAt := time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer access-token" {
			t.Fatalf("Authorization = %q, want bearer token", r.Header.Get("Authorization"))
		}
		switch r.URL.Path {
		case "/api/v1/sync/push":
			if r.Method != http.MethodPost {
				t.Fatalf("push method = %s, want POST", r.Method)
			}
			var request pushRequest
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Fatalf("decode push request: %v", err)
			}
			if len(request.Items) != 1 || request.Items[0].BaseRevision != 2 {
				t.Fatalf("push request = %+v, want one item revision 2", request)
			}
			writeJSON(t, w, http.StatusOK, PushResponse{
				Applied: []SyncItem{
					{
						ID:               "item-1",
						ServerRevision:   3,
						EncryptedPayload: base64.StdEncoding.EncodeToString([]byte("ciphertext")),
						PayloadNonce:     base64.StdEncoding.EncodeToString([]byte("nonce")),
						PayloadVersion:   1,
						UpdatedAt:        updatedAt,
					},
				},
				CurrentRevision: 3,
			})
		case "/api/v1/sync/changes":
			if r.URL.Query().Get("since_revision") != "3" {
				t.Fatalf("since_revision = %q, want 3", r.URL.Query().Get("since_revision"))
			}
			writeJSON(t, w, http.StatusOK, Changes{
				Items: []SyncItem{
					{
						ID:               "remote-1",
						ServerRevision:   4,
						EncryptedPayload: base64.StdEncoding.EncodeToString([]byte("remote")),
						PayloadNonce:     base64.StdEncoding.EncodeToString([]byte("nonce")),
						PayloadVersion:   1,
						UpdatedAt:        updatedAt,
					},
				},
				CurrentRevision: 4,
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client, err := New(server.URL, server.Client())
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}

	push, err := client.PushChanges(context.Background(), "access-token", []PushItem{
		{
			ID:               "item-1",
			BaseRevision:     2,
			EncryptedPayload: base64.StdEncoding.EncodeToString([]byte("ciphertext")),
			PayloadNonce:     base64.StdEncoding.EncodeToString([]byte("nonce")),
			PayloadVersion:   1,
		},
	})
	if err != nil {
		t.Fatalf("PushChanges returned error: %v", err)
	}
	if push.CurrentRevision != 3 || len(push.Applied) != 1 {
		t.Fatalf("PushChanges = %+v, want applied item", push)
	}

	changes, err := client.PullChanges(context.Background(), "access-token", 3)
	if err != nil {
		t.Fatalf("PullChanges returned error: %v", err)
	}
	if changes.CurrentRevision != 4 || changes.Items[0].ID != "remote-1" {
		t.Fatalf("PullChanges = %+v, want remote item", changes)
	}
}

func TestClientPullChangesAllowsLargeResponses(t *testing.T) {
	updatedAt := time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)
	largePayload := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte("x"), 4<<20))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/sync/changes" {
			http.NotFound(w, r)
			return
		}
		writeJSON(t, w, http.StatusOK, Changes{
			Items: []SyncItem{
				{
					ID:               "large-file",
					ServerRevision:   1,
					EncryptedPayload: largePayload,
					PayloadNonce:     base64.StdEncoding.EncodeToString([]byte("nonce")),
					PayloadVersion:   1,
					UpdatedAt:        updatedAt,
				},
			},
			CurrentRevision: 1,
		})
	}))
	defer server.Close()

	client, err := New(server.URL, server.Client())
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}

	changes, err := client.PullChanges(context.Background(), "access-token", 0)
	if err != nil {
		t.Fatalf("PullChanges returned error: %v", err)
	}
	if len(changes.Items) != 1 || changes.Items[0].EncryptedPayload != largePayload {
		t.Fatalf("PullChanges returned payload length %d, want %d", len(changes.Items[0].EncryptedPayload), len(largePayload))
	}
}

func TestClientSyncRequiresAccessToken(t *testing.T) {
	client, err := New("http://localhost:8080", nil)
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}
	if _, err = client.PullChanges(context.Background(), "", 0); err == nil {
		t.Fatal("PullChanges returned nil error for empty token")
	}
	if _, err = client.PushChanges(context.Background(), "", nil); err == nil {
		t.Fatal("PushChanges returned nil error for empty token")
	}
}
