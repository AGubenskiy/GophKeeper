package localstore

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestStoreProfileSessionAndStatus(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 7, 3, 10, 0, 0, 0, time.UTC)

	profile := Profile{
		ServerURL:    "http://localhost:8080",
		UserID:       "user-1",
		Login:        "alice",
		ClientID:     "client-1",
		AuthSalt:     []byte("auth-salt"),
		VaultSalt:    []byte("vault-salt"),
		KDFParams:    []byte(`{"algorithm":"argon2id"}`),
		LastRevision: 7,
		UpdatedAt:    now,
	}
	if err := store.SaveProfile(ctx, profile); err != nil {
		t.Fatalf("SaveProfile returned error: %v", err)
	}

	gotProfile, err := store.Profile(ctx)
	if err != nil {
		t.Fatalf("Profile returned error: %v", err)
	}
	if gotProfile.Login != profile.Login || gotProfile.LastRevision != profile.LastRevision {
		t.Fatalf("Profile = %+v, want %+v", gotProfile, profile)
	}

	session := Session{
		AccessToken:      "access",
		AccessExpiresAt:  now.Add(time.Minute),
		RefreshToken:     "refresh",
		RefreshExpiresAt: now.Add(time.Hour),
		UpdatedAt:        now,
	}
	if err = store.SaveSession(ctx, session); err != nil {
		t.Fatalf("SaveSession returned error: %v", err)
	}

	gotSession, err := store.Session(ctx)
	if err != nil {
		t.Fatalf("Session returned error: %v", err)
	}
	if gotSession.AccessToken != session.AccessToken || gotSession.RefreshToken != session.RefreshToken {
		t.Fatalf("Session = %+v, want %+v", gotSession, session)
	}

	status, err := store.Status(ctx)
	if err != nil {
		t.Fatalf("Status returned error: %v", err)
	}
	if !status.HasProfile || !status.HasSession || status.Login != "alice" || status.LastRevision != 7 {
		t.Fatalf("Status = %+v, want stored profile/session", status)
	}

	if err = store.ClearSession(ctx); err != nil {
		t.Fatalf("ClearSession returned error: %v", err)
	}
	if _, err = store.Session(ctx); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Session error = %v, want ErrNotFound", err)
	}
}

func TestStoreReportsMissingProfileAndSession(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()

	if _, err := store.Profile(ctx); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Profile error = %v, want ErrNotFound", err)
	}
	if _, err := store.Session(ctx); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Session error = %v, want ErrNotFound", err)
	}

	status, err := store.Status(ctx)
	if err != nil {
		t.Fatalf("Status returned error: %v", err)
	}
	if status.HasProfile || status.HasSession {
		t.Fatalf("Status = %+v, want empty store", status)
	}
}

func TestStoreItemCRUDAndStatus(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 7, 3, 10, 0, 0, 0, time.UTC)

	item := Item{
		ID:               "item-1",
		ServerRevision:   3,
		EncryptedPayload: []byte("ciphertext"),
		PayloadNonce:     []byte("nonce"),
		PayloadVersion:   1,
		DirtyState:       DirtyStateUpsert,
		UpdatedAt:        now,
	}
	if err := store.SaveItem(ctx, item); err != nil {
		t.Fatalf("SaveItem returned error: %v", err)
	}

	got, err := store.Item(ctx, "item-1")
	if err != nil {
		t.Fatalf("Item returned error: %v", err)
	}
	if got.ID != item.ID || got.ServerRevision != item.ServerRevision || got.PayloadVersion != 1 {
		t.Fatalf("Item = %+v, want %+v", got, item)
	}

	items, err := store.ListItems(ctx, false)
	if err != nil {
		t.Fatalf("ListItems returned error: %v", err)
	}
	if len(items) != 1 || items[0].ID != "item-1" {
		t.Fatalf("ListItems = %+v, want item-1", items)
	}

	status, err := store.Status(ctx)
	if err != nil {
		t.Fatalf("Status returned error: %v", err)
	}
	if status.ItemCount != 1 || status.DirtyCount != 1 {
		t.Fatalf("Status = %+v, want one dirty item", status)
	}

	if err = store.DeleteItem(ctx, "item-1", now.Add(time.Minute)); err != nil {
		t.Fatalf("DeleteItem returned error: %v", err)
	}
	items, err = store.ListItems(ctx, false)
	if err != nil {
		t.Fatalf("ListItems returned error: %v", err)
	}
	if len(items) != 0 {
		t.Fatalf("ListItems returned deleted items: %+v", items)
	}
	items, err = store.ListItems(ctx, true)
	if err != nil {
		t.Fatalf("ListItems returned error: %v", err)
	}
	if len(items) != 1 || items[0].DeletedAt == nil || items[0].DirtyState != DirtyStateDelete {
		t.Fatalf("deleted item = %+v, want tombstone", items)
	}
}

func TestStoreConflictCRUDAndStatus(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 7, 3, 10, 0, 0, 0, time.UTC)

	local := Item{
		ID:               "item-1",
		ServerRevision:   2,
		EncryptedPayload: []byte("local"),
		PayloadNonce:     []byte("local-nonce"),
		PayloadVersion:   1,
		DirtyState:       DirtyStateConflict,
		UpdatedAt:        now,
	}
	if err := store.SaveItem(ctx, local); err != nil {
		t.Fatalf("SaveItem returned error: %v", err)
	}
	remote := Item{
		ID:               "item-1",
		ServerRevision:   5,
		EncryptedPayload: []byte("remote"),
		PayloadNonce:     []byte("remote-nonce"),
		PayloadVersion:   1,
		DirtyState:       DirtyStateClean,
		UpdatedAt:        now.Add(time.Minute),
	}
	if err := store.SaveConflict(ctx, Conflict{
		ItemID:        "item-1",
		Reason:        "revision_mismatch",
		LocalRevision: 2,
		RemoteItem:    &remote,
		CreatedAt:     now,
		UpdatedAt:     now.Add(time.Minute),
	}); err != nil {
		t.Fatalf("SaveConflict returned error: %v", err)
	}

	got, err := store.Conflict(ctx, "item-1")
	if err != nil {
		t.Fatalf("Conflict returned error: %v", err)
	}
	if got.RemoteItem == nil || got.RemoteItem.ServerRevision != 5 || string(got.RemoteItem.EncryptedPayload) != "remote" {
		t.Fatalf("Conflict = %+v, want stored remote item", got)
	}
	conflicts, err := store.ListConflicts(ctx)
	if err != nil {
		t.Fatalf("ListConflicts returned error: %v", err)
	}
	if len(conflicts) != 1 || conflicts[0].ItemID != "item-1" {
		t.Fatalf("ListConflicts = %+v, want one conflict", conflicts)
	}
	status, err := store.Status(ctx)
	if err != nil {
		t.Fatalf("Status returned error: %v", err)
	}
	if status.ConflictCount != 1 || status.DirtyCount != 1 {
		t.Fatalf("Status = %+v, want one conflict and one dirty item", status)
	}

	if err = store.ClearConflict(ctx, "item-1"); err != nil {
		t.Fatalf("ClearConflict returned error: %v", err)
	}
	if _, err = store.Conflict(ctx, "item-1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Conflict error = %v, want ErrNotFound", err)
	}
}

func TestStoreSyncTransactionHelpers(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 7, 3, 10, 0, 0, 0, time.UTC)

	local := Item{
		ID:               "item-1",
		ServerRevision:   2,
		EncryptedPayload: []byte("local"),
		PayloadNonce:     []byte("local-nonce"),
		PayloadVersion:   1,
		DirtyState:       DirtyStateConflict,
		UpdatedAt:        now,
	}
	remote := Item{
		ID:               "item-1",
		ServerRevision:   5,
		EncryptedPayload: []byte("remote"),
		PayloadNonce:     []byte("remote-nonce"),
		PayloadVersion:   1,
		DirtyState:       DirtyStateClean,
		UpdatedAt:        now,
	}
	if err := store.SaveItemAndConflict(ctx, local, Conflict{
		ItemID:        "item-1",
		Reason:        "revision_mismatch",
		LocalRevision: 2,
		RemoteItem:    &remote,
		CreatedAt:     now,
		UpdatedAt:     now,
	}); err != nil {
		t.Fatalf("SaveItemAndConflict returned error: %v", err)
	}
	if got, err := store.Conflict(ctx, "item-1"); err != nil || got.RemoteItem == nil {
		t.Fatalf("Conflict = %+v, err = %v, want stored conflict", got, err)
	}

	clean := remote
	clean.DirtyState = DirtyStateClean
	if err := store.SaveItemAndClearConflict(ctx, clean); err != nil {
		t.Fatalf("SaveItemAndClearConflict returned error: %v", err)
	}
	if _, err := store.Conflict(ctx, "item-1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Conflict error = %v, want ErrNotFound", err)
	}
	if got, err := store.Item(ctx, "item-1"); err != nil || got.ServerRevision != 5 || got.DirtyState != DirtyStateClean {
		t.Fatalf("Item = %+v, err = %v, want clean remote item", got, err)
	}
}

func TestStoreSaveItemAndConflictRollsBackOnInvalidConflict(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 7, 3, 10, 0, 0, 0, time.UTC)

	item := Item{
		ID:               "item-rollback",
		ServerRevision:   1,
		EncryptedPayload: []byte("local"),
		PayloadNonce:     []byte("local-nonce"),
		PayloadVersion:   1,
		DirtyState:       DirtyStateConflict,
		UpdatedAt:        now,
	}
	remote := Item{
		ID:               "different-item",
		ServerRevision:   2,
		EncryptedPayload: []byte("remote"),
		PayloadNonce:     []byte("remote-nonce"),
		PayloadVersion:   1,
		DirtyState:       DirtyStateClean,
		UpdatedAt:        now,
	}
	err := store.SaveItemAndConflict(ctx, item, Conflict{
		ItemID:        "item-rollback",
		Reason:        "revision_mismatch",
		LocalRevision: 1,
		RemoteItem:    &remote,
	})
	if err == nil {
		t.Fatal("SaveItemAndConflict returned nil error for invalid conflict")
	}
	if _, itemErr := store.Item(ctx, "item-rollback"); !errors.Is(itemErr, ErrNotFound) {
		t.Fatalf("Item error = %v, want rollback and ErrNotFound", itemErr)
	}
}

func TestStoreValidation(t *testing.T) {
	if err := (Profile{}).Validate(); err == nil {
		t.Fatal("Profile Validate returned nil error, want validation error")
	}
	if err := (Session{}).Validate(); err == nil {
		t.Fatal("Session Validate returned nil error, want validation error")
	}
	if err := (Item{}).Validate(); err == nil {
		t.Fatal("Item Validate returned nil error, want validation error")
	}
	if err := (Conflict{}).Validate(); err == nil {
		t.Fatal("Conflict Validate returned nil error, want validation error")
	}
	if _, err := Open(""); err == nil {
		t.Fatal("Open returned nil error for empty path")
	}
}

func openTestStore(t *testing.T) *Store {
	t.Helper()

	store, err := Open(filepath.Join(t.TempDir(), "client.db"))
	if err != nil {
		t.Fatalf("Open returned error: %v", err)
	}
	t.Cleanup(func() {
		_ = store.Close()
	})
	return store
}
