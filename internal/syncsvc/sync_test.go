package syncsvc

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/AGubenskiy/GophKeeper/internal/domain"
)

func TestPushAppliesNewUpdateAndDelete(t *testing.T) {
	items := newFakeItemRepo()
	revisions := &fakeRevisionRepo{state: domain.SyncState{UserID: "user-1", CurrentRevision: 0}}
	service := newTestService(t, items, revisions)
	deletedAt := testNow().Add(time.Minute)

	result, err := service.Push(context.Background(), "user-1", []Mutation{
		testMutation("item-1", 0),
		{
			ID:               "item-2",
			BaseRevision:     0,
			EncryptedPayload: []byte("deleted-ciphertext"),
			PayloadNonce:     []byte("deleted-nonce"),
			PayloadVersion:   1,
			DeletedAt:        &deletedAt,
		},
	})
	if err != nil {
		t.Fatalf("Push returned error: %v", err)
	}
	if len(result.Applied) != 2 || result.CurrentRevision != 2 {
		t.Fatalf("Push result = %+v, want two applied revisions", result)
	}
	if got := items.items["item-2"]; got.DeletedAt == nil || got.ServerRevision != 2 {
		t.Fatalf("deleted item = %+v, want tombstone revision 2", got)
	}
}

func TestPushReturnsConflictOnRevisionMismatch(t *testing.T) {
	items := newFakeItemRepo()
	items.items["item-1"] = domain.VaultItem{
		ID:               "item-1",
		UserID:           "user-1",
		ServerRevision:   7,
		EncryptedPayload: []byte("remote"),
		PayloadNonce:     []byte("nonce"),
		PayloadVersion:   1,
		CreatedAt:        testNow(),
		UpdatedAt:        testNow(),
	}
	revisions := &fakeRevisionRepo{state: domain.SyncState{UserID: "user-1", CurrentRevision: 7}}
	service := newTestService(t, items, revisions)

	result, err := service.Push(context.Background(), "user-1", []Mutation{testMutation("item-1", 3)})
	if err != nil {
		t.Fatalf("Push returned error: %v", err)
	}
	if len(result.Applied) != 0 || len(result.Conflicts) != 1 {
		t.Fatalf("Push result = %+v, want one conflict", result)
	}
	if result.Conflicts[0].ServerRevision != 7 || result.Conflicts[0].Remote == nil {
		t.Fatalf("conflict = %+v, want remote revision", result.Conflicts[0])
	}
}

func TestPullReturnsChangesAndCurrentRevision(t *testing.T) {
	items := newFakeItemRepo()
	items.items["old"] = domain.VaultItem{ID: "old", UserID: "user-1", ServerRevision: 1, EncryptedPayload: []byte("old"), PayloadNonce: []byte("nonce"), PayloadVersion: 1}
	items.items["new"] = domain.VaultItem{ID: "new", UserID: "user-1", ServerRevision: 3, EncryptedPayload: []byte("new"), PayloadNonce: []byte("nonce"), PayloadVersion: 1}
	revisions := &fakeRevisionRepo{state: domain.SyncState{UserID: "user-1", CurrentRevision: 3}}
	service := newTestService(t, items, revisions)

	changes, err := service.Pull(context.Background(), "user-1", 1, 10)
	if err != nil {
		t.Fatalf("Pull returned error: %v", err)
	}
	if changes.CurrentRevision != 3 || len(changes.Items) != 1 || changes.Items[0].ID != "new" {
		t.Fatalf("Changes = %+v, want only new item", changes)
	}
}

func TestPushUsesAtomicMutationRepositoryWhenAvailable(t *testing.T) {
	items := &fakeAtomicItemRepo{}
	revisions := &fakeRevisionRepo{state: domain.SyncState{UserID: "user-1", CurrentRevision: 9}}
	service := newTestService(t, items, revisions)

	result, err := service.Push(context.Background(), "user-1", []Mutation{testMutation("item-1", 0)})
	if err != nil {
		t.Fatalf("Push returned error: %v", err)
	}
	if items.applied != 1 {
		t.Fatalf("atomic applied count = %d, want 1", items.applied)
	}
	if len(result.Applied) != 1 || result.Applied[0].ServerRevision != 10 || result.CurrentRevision != 10 {
		t.Fatalf("Push result = %+v, want atomic revision 10", result)
	}
}

func TestValidationAndConstructorErrors(t *testing.T) {
	if _, err := NewService(nil, &fakeRevisionRepo{}, nil); err == nil {
		t.Fatal("NewService returned nil error for missing item repo")
	}
	service := newTestService(t, newFakeItemRepo(), &fakeRevisionRepo{state: domain.SyncState{UserID: "user-1"}})
	if _, err := service.Pull(context.Background(), "", 0, 0); !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("Pull error = %v, want validation", err)
	}
	if _, err := service.Push(context.Background(), "user-1", []Mutation{{ID: "bad"}}); !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("Push error = %v, want validation", err)
	}
}

func newTestService(t *testing.T, items ItemRepository, revisions RevisionRepository) *Service {
	t.Helper()

	service, err := NewService(items, revisions, testNow)
	if err != nil {
		t.Fatalf("NewService returned error: %v", err)
	}
	return service
}

func testMutation(id string, baseRevision int64) Mutation {
	return Mutation{
		ID:               id,
		BaseRevision:     baseRevision,
		EncryptedPayload: []byte("ciphertext"),
		PayloadNonce:     []byte("nonce"),
		PayloadVersion:   1,
	}
}

func testNow() time.Time {
	return time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)
}

type fakeItemRepo struct {
	items map[string]domain.VaultItem
}

func newFakeItemRepo() *fakeItemRepo {
	return &fakeItemRepo{items: map[string]domain.VaultItem{}}
}

func (r *fakeItemRepo) Upsert(_ context.Context, item domain.VaultItem) error {
	r.items[item.ID] = item.Clone()
	return nil
}

func (r *fakeItemRepo) Find(_ context.Context, userID, itemID string) (domain.VaultItem, error) {
	item, ok := r.items[itemID]
	if !ok || item.UserID != userID {
		return domain.VaultItem{}, domain.ErrNotFound
	}
	return item.Clone(), nil
}

func (r *fakeItemRepo) ListChanged(_ context.Context, userID string, sinceRevision int64, limit int) ([]domain.VaultItem, error) {
	out := make([]domain.VaultItem, 0)
	for _, item := range r.items {
		if item.UserID == userID && item.ServerRevision > sinceRevision {
			out = append(out, item.Clone())
			if len(out) == limit {
				break
			}
		}
	}
	return out, nil
}

type fakeAtomicItemRepo struct {
	applied int
}

func (r *fakeAtomicItemRepo) ApplyMutation(_ context.Context, userID string, mutation Mutation, now time.Time) (domain.VaultItem, *Conflict, error) {
	r.applied++
	return domain.VaultItem{
		ID:               mutation.ID,
		UserID:           userID,
		ServerRevision:   10,
		EncryptedPayload: append([]byte(nil), mutation.EncryptedPayload...),
		PayloadNonce:     append([]byte(nil), mutation.PayloadNonce...),
		PayloadVersion:   mutation.PayloadVersion,
		CreatedAt:        now,
		UpdatedAt:        now,
	}, nil, nil
}

func (r *fakeAtomicItemRepo) Upsert(context.Context, domain.VaultItem) error {
	return errors.New("non-atomic upsert should not be called")
}

func (r *fakeAtomicItemRepo) Find(context.Context, string, string) (domain.VaultItem, error) {
	return domain.VaultItem{}, errors.New("non-atomic find should not be called")
}

func (r *fakeAtomicItemRepo) ListChanged(context.Context, string, int64, int) ([]domain.VaultItem, error) {
	return nil, errors.New("list changed should not be called in push")
}

type fakeRevisionRepo struct {
	state domain.SyncState
}

func (r *fakeRevisionRepo) Get(context.Context, string) (domain.SyncState, error) {
	return r.state, nil
}

func (r *fakeRevisionRepo) Increment(context.Context, string) (int64, error) {
	r.state.CurrentRevision++
	return r.state.CurrentRevision, nil
}
