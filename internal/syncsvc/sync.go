package syncsvc

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/AGubenskiy/GophKeeper/internal/domain"
)

const defaultChangeLimit = 500

// ItemRepository stores encrypted vault items.
type ItemRepository interface {
	Upsert(ctx context.Context, item domain.VaultItem) error
	Find(ctx context.Context, userID, itemID string) (domain.VaultItem, error)
	ListChanged(ctx context.Context, userID string, sinceRevision int64, limit int) ([]domain.VaultItem, error)
}

// RevisionRepository stores per-user sync revisions.
type RevisionRepository interface {
	Get(ctx context.Context, userID string) (domain.SyncState, error)
	Increment(ctx context.Context, userID string) (int64, error)
}

// AtomicMutationRepository applies one sync mutation without splitting revision and item updates.
type AtomicMutationRepository interface {
	ApplyMutation(ctx context.Context, userID string, mutation Mutation, now time.Time) (domain.VaultItem, *Conflict, error)
}

// Mutation is one client-side encrypted item change.
type Mutation struct {
	ID               string
	BaseRevision     int64
	EncryptedPayload []byte
	PayloadNonce     []byte
	PayloadVersion   int16
	DeletedAt        *time.Time
}

// Changes contains server-side changes after a client revision.
type Changes struct {
	Items           []domain.VaultItem
	CurrentRevision int64
}

// PushResult describes applied mutations and optimistic-lock conflicts.
type PushResult struct {
	Applied         []domain.VaultItem
	Conflicts       []Conflict
	CurrentRevision int64
}

// Conflict reports a mutation rejected by optimistic concurrency checks.
type Conflict struct {
	ID             string
	BaseRevision   int64
	ServerRevision int64
	Reason         string
	Remote         *domain.VaultItem
}

// Service implements encrypted item push/pull synchronization.
type Service struct {
	items     ItemRepository
	revisions RevisionRepository
	now       func() time.Time
}

// NewService creates a sync service.
func NewService(items ItemRepository, revisions RevisionRepository, now func() time.Time) (*Service, error) {
	if items == nil {
		return nil, errors.New("item repository is required")
	}
	if revisions == nil {
		return nil, errors.New("revision repository is required")
	}
	if now == nil {
		now = time.Now
	}
	return &Service{
		items:     items,
		revisions: revisions,
		now:       now,
	}, nil
}

// Pull returns encrypted item changes after sinceRevision.
func (s *Service) Pull(ctx context.Context, userID string, sinceRevision int64, limit int) (Changes, error) {
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return Changes{}, fmt.Errorf("%w: user id is required", domain.ErrValidation)
	}
	if sinceRevision < 0 {
		return Changes{}, fmt.Errorf("%w: since revision must be non-negative", domain.ErrValidation)
	}
	if limit <= 0 {
		limit = defaultChangeLimit
	}

	state, err := s.revisions.Get(ctx, userID)
	if err != nil {
		return Changes{}, err
	}
	items, err := s.items.ListChanged(ctx, userID, sinceRevision, limit)
	if err != nil {
		return Changes{}, err
	}
	return Changes{Items: cloneItems(items), CurrentRevision: state.CurrentRevision}, nil
}

// Push applies encrypted client mutations and returns conflicts without overwriting them.
func (s *Service) Push(ctx context.Context, userID string, mutations []Mutation) (PushResult, error) {
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return PushResult{}, fmt.Errorf("%w: user id is required", domain.ErrValidation)
	}

	result := PushResult{
		Applied:   make([]domain.VaultItem, 0, len(mutations)),
		Conflicts: make([]Conflict, 0),
	}
	for _, mutation := range mutations {
		applied, conflict, err := s.applyMutation(ctx, userID, mutation)
		if err != nil {
			return PushResult{}, err
		}
		if conflict != nil {
			result.Conflicts = append(result.Conflicts, *conflict)
			continue
		}
		result.Applied = append(result.Applied, applied)
		result.CurrentRevision = maxInt64(result.CurrentRevision, applied.ServerRevision)
	}

	state, err := s.revisions.Get(ctx, userID)
	if err != nil {
		return PushResult{}, err
	}
	result.CurrentRevision = maxInt64(result.CurrentRevision, state.CurrentRevision)
	return result, nil
}

func (s *Service) applyMutation(ctx context.Context, userID string, mutation Mutation) (domain.VaultItem, *Conflict, error) {
	if atomic, ok := s.items.(AtomicMutationRepository); ok {
		return atomic.ApplyMutation(ctx, userID, mutation, s.now().UTC())
	}
	return s.applyMutationFallback(ctx, userID, mutation)
}

func (s *Service) applyMutationFallback(ctx context.Context, userID string, mutation Mutation) (domain.VaultItem, *Conflict, error) {
	if err := mutation.Validate(); err != nil {
		return domain.VaultItem{}, nil, err
	}

	current, err := s.items.Find(ctx, userID, mutation.ID)
	switch {
	case err == nil:
		if current.ServerRevision != mutation.BaseRevision {
			remote := current.Clone()
			return domain.VaultItem{}, &Conflict{
				ID:             mutation.ID,
				BaseRevision:   mutation.BaseRevision,
				ServerRevision: current.ServerRevision,
				Reason:         "revision_mismatch",
				Remote:         &remote,
			}, nil
		}
	case errors.Is(err, domain.ErrNotFound):
		if mutation.BaseRevision != 0 {
			return domain.VaultItem{}, &Conflict{
				ID:           mutation.ID,
				BaseRevision: mutation.BaseRevision,
				Reason:       "missing_remote_item",
			}, nil
		}
	default:
		return domain.VaultItem{}, nil, err
	}

	revision, err := s.revisions.Increment(ctx, userID)
	if err != nil {
		return domain.VaultItem{}, nil, err
	}

	now := s.now().UTC()
	item := domain.VaultItem{
		ID:               mutation.ID,
		UserID:           userID,
		ServerRevision:   revision,
		EncryptedPayload: append([]byte(nil), mutation.EncryptedPayload...),
		PayloadNonce:     append([]byte(nil), mutation.PayloadNonce...),
		PayloadVersion:   mutation.PayloadVersion,
		DeletedAt:        cloneTimePtr(mutation.DeletedAt),
		CreatedAt:        now,
		UpdatedAt:        now,
	}
	if current.ID != "" {
		item.CreatedAt = current.CreatedAt
	}
	if item.DeletedAt != nil {
		item.UpdatedAt = item.DeletedAt.UTC()
	}

	if err = s.items.Upsert(ctx, item); err != nil {
		return domain.VaultItem{}, nil, err
	}
	return item.Clone(), nil, nil
}

// Validate checks a mutation before applying it.
func (m Mutation) Validate() error {
	if strings.TrimSpace(m.ID) == "" {
		return fmt.Errorf("%w: item id is required", domain.ErrValidation)
	}
	if m.BaseRevision < 0 {
		return fmt.Errorf("%w: base revision must be non-negative", domain.ErrValidation)
	}
	if len(m.EncryptedPayload) == 0 {
		return fmt.Errorf("%w: encrypted payload is required", domain.ErrValidation)
	}
	if len(m.PayloadNonce) == 0 {
		return fmt.Errorf("%w: payload nonce is required", domain.ErrValidation)
	}
	if m.PayloadVersion <= 0 {
		return fmt.Errorf("%w: payload version must be positive", domain.ErrValidation)
	}
	return nil
}

func cloneItems(items []domain.VaultItem) []domain.VaultItem {
	out := make([]domain.VaultItem, 0, len(items))
	for _, item := range items {
		out = append(out, item.Clone())
	}
	return out
}

func cloneTimePtr(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	cloned := value.UTC()
	return &cloned
}

func maxInt64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}
