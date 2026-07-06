package clientapp

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/AGubenskiy/GophKeeper/internal/clientapi"
	"github.com/AGubenskiy/GophKeeper/internal/localstore"
	"github.com/spf13/cobra"
)

type syncSummary struct {
	pushed    int
	pulled    int
	conflicts int
}

const accessTokenRefreshSkew = 30 * time.Second

func newSyncCommand(deps dependencies, rootOpts *rootOptions) *cobra.Command {
	return &cobra.Command{
		Use:   "sync",
		Short: "Synchronize encrypted vault items with the server",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			store, err := openStore(rootOpts, deps)
			if err != nil {
				return err
			}
			defer closeStore(store)

			summary, err := syncVault(cmd.Context(), deps, store)
			if err != nil {
				return err
			}
			_, _ = fmt.Fprintf(deps.stdout, "Sync complete: pushed %d, pulled %d, conflicts %d\n", summary.pushed, summary.pulled, summary.conflicts)
			if summary.conflicts > 0 {
				_, _ = fmt.Fprintln(deps.stdout, "Resolve conflicts with: gk conflict list")
			}
			return nil
		},
	}
}

func syncVault(ctx context.Context, deps dependencies, store clientStore) (syncSummary, error) {
	profile, err := store.Profile(ctx)
	if err != nil {
		if errors.Is(err, localstore.ErrNotFound) {
			return syncSummary{}, errors.New("local profile not found; run login first")
		}
		return syncSummary{}, err
	}
	session, err := store.Session(ctx)
	if err != nil {
		if errors.Is(err, localstore.ErrNotFound) {
			return syncSummary{}, errors.New("local session not found; run login first")
		}
		return syncSummary{}, err
	}

	api, err := deps.apiFactory(profile.ServerURL)
	if err != nil {
		return syncSummary{}, err
	}

	session, err = refreshSessionIfNeeded(ctx, deps, store, api, session)
	if err != nil {
		return syncSummary{}, err
	}

	summary := syncSummary{}
	dirty, err := dirtyItems(ctx, store)
	if err != nil {
		return syncSummary{}, err
	}
	if len(dirty) > 0 {
		var pushResult clientapi.PushResponse
		pushResult, session, err = pushChangesWithSessionRefresh(ctx, deps, store, api, session, pushItemsFromLocal(dirty))
		if err != nil {
			return syncSummary{}, err
		}
		if err = applyPushResult(ctx, store, dirty, pushResult); err != nil {
			return syncSummary{}, err
		}
		summary.pushed = len(pushResult.Applied)
		summary.conflicts += len(pushResult.Conflicts)
	}

	pullSummary, finalRevision, err := pullAllChanges(ctx, deps, store, api, session, profile.LastRevision)
	if err != nil {
		return syncSummary{}, err
	}
	summary.pulled = pullSummary.pulled
	summary.conflicts += pullSummary.conflicts

	profile.LastRevision = finalRevision
	profile.UpdatedAt = deps.now().UTC()
	if err = store.SaveProfile(ctx, profile); err != nil {
		return syncSummary{}, err
	}
	return summary, nil
}

func refreshSessionIfNeeded(ctx context.Context, deps dependencies, store clientStore, api authAPI, session localstore.Session) (localstore.Session, error) {
	now := deps.now().UTC()
	if session.AccessExpiresAt.After(now.Add(accessTokenRefreshSkew)) {
		return session, nil
	}
	return refreshSession(ctx, deps, store, api, session)
}

func pushChangesWithSessionRefresh(
	ctx context.Context,
	deps dependencies,
	store clientStore,
	api authAPI,
	session localstore.Session,
	items []clientapi.PushItem,
) (clientapi.PushResponse, localstore.Session, error) {
	result, err := api.PushChanges(ctx, session.AccessToken, items)
	if err == nil || !isUnauthorizedAPIError(err) {
		return result, session, err
	}

	session, refreshErr := refreshSession(ctx, deps, store, api, session)
	if refreshErr != nil {
		return clientapi.PushResponse{}, session, refreshErr
	}
	result, err = api.PushChanges(ctx, session.AccessToken, items)
	return result, session, err
}

func pullChangesWithSessionRefresh(
	ctx context.Context,
	deps dependencies,
	store clientStore,
	api authAPI,
	session localstore.Session,
	sinceRevision int64,
) (clientapi.Changes, localstore.Session, error) {
	result, err := api.PullChanges(ctx, session.AccessToken, sinceRevision)
	if err == nil || !isUnauthorizedAPIError(err) {
		return result, session, err
	}

	session, refreshErr := refreshSession(ctx, deps, store, api, session)
	if refreshErr != nil {
		return clientapi.Changes{}, session, refreshErr
	}
	result, err = api.PullChanges(ctx, session.AccessToken, sinceRevision)
	return result, session, err
}

func pullAllChanges(
	ctx context.Context,
	deps dependencies,
	store clientStore,
	api authAPI,
	session localstore.Session,
	sinceRevision int64,
) (syncSummary, int64, error) {
	summary := syncSummary{}
	finalRevision := sinceRevision

	for {
		changes, updatedSession, err := pullChangesWithSessionRefresh(ctx, deps, store, api, session, finalRevision)
		if err != nil {
			return syncSummary{}, 0, err
		}
		session = updatedSession

		pulled, conflicts, err := applyPulledChanges(ctx, store, changes.Items)
		if err != nil {
			return syncSummary{}, 0, err
		}
		summary.pulled += pulled
		summary.conflicts += conflicts

		lastReceivedRevision := maxSyncItemRevision(changes.Items)
		if lastReceivedRevision > finalRevision {
			finalRevision = lastReceivedRevision
		}
		if finalRevision >= changes.CurrentRevision {
			finalRevision = changes.CurrentRevision
			return summary, finalRevision, nil
		}
		if len(changes.Items) == 0 {
			// Avoid a retry loop if the server reports a revision that has no visible item changes.
			finalRevision = changes.CurrentRevision
			return summary, finalRevision, nil
		}
	}
}

func refreshSession(ctx context.Context, deps dependencies, store clientStore, api authAPI, session localstore.Session) (localstore.Session, error) {
	now := deps.now().UTC()
	if !session.RefreshExpiresAt.After(now) {
		return localstore.Session{}, errors.New("local session has expired; run login first")
	}

	refreshed, err := api.Refresh(ctx, session.RefreshToken)
	if err != nil {
		return localstore.Session{}, fmt.Errorf("refresh session: %w", err)
	}

	updated := localstore.Session{
		AccessToken:      refreshed.AccessToken,
		AccessExpiresAt:  refreshed.AccessExpiresAt,
		RefreshToken:     refreshed.RefreshToken,
		RefreshExpiresAt: refreshed.RefreshExpiresAt,
		UpdatedAt:        now,
	}
	if err = store.SaveSession(ctx, updated); err != nil {
		return localstore.Session{}, err
	}
	return updated, nil
}

func isUnauthorizedAPIError(err error) bool {
	var apiErr *clientapi.Error
	return errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusUnauthorized
}

func dirtyItems(ctx context.Context, store clientStore) ([]localstore.Item, error) {
	items, err := store.ListItems(ctx, true)
	if err != nil {
		return nil, err
	}

	dirty := make([]localstore.Item, 0)
	for _, item := range items {
		switch item.DirtyState {
		case localstore.DirtyStateUpsert, localstore.DirtyStateDelete:
			dirty = append(dirty, item.Clone())
		}
	}
	return dirty, nil
}

func pushItemsFromLocal(items []localstore.Item) []clientapi.PushItem {
	out := make([]clientapi.PushItem, 0, len(items))
	for _, item := range items {
		out = append(out, clientapi.PushItem{
			ID:               item.ID,
			BaseRevision:     item.ServerRevision,
			EncryptedPayload: base64.StdEncoding.EncodeToString(item.EncryptedPayload),
			PayloadNonce:     base64.StdEncoding.EncodeToString(item.PayloadNonce),
			PayloadVersion:   item.PayloadVersion,
			DeletedAt:        cloneTimePtr(item.DeletedAt),
		})
	}
	return out
}

func applyPushResult(ctx context.Context, store clientStore, dirty []localstore.Item, result clientapi.PushResponse) error {
	dirtyByID := make(map[string]localstore.Item, len(dirty))
	for _, item := range dirty {
		dirtyByID[item.ID] = item.Clone()
	}
	for _, applied := range result.Applied {
		item, err := localItemFromSync(applied, localstore.DirtyStateClean)
		if err != nil {
			return err
		}
		if err = store.SaveItemAndClearConflict(ctx, item); err != nil {
			return err
		}
	}
	for _, conflict := range result.Conflicts {
		item, ok := dirtyByID[conflict.ID]
		if !ok {
			continue
		}
		item.DirtyState = localstore.DirtyStateConflict
		item.UpdatedAt = time.Now().UTC()
		storedConflict, err := conflictFromPush(item, conflict)
		if err != nil {
			return err
		}
		if err := store.SaveItemAndConflict(ctx, item, storedConflict); err != nil {
			return err
		}
	}
	return nil
}

func applyPulledChanges(ctx context.Context, store clientStore, remoteItems []clientapi.SyncItem) (int, int, error) {
	pulled := 0
	conflicts := 0

	for _, remote := range remoteItems {
		remoteItem, err := localItemFromSync(remote, localstore.DirtyStateClean)
		if err != nil {
			return 0, 0, err
		}

		local, err := store.Item(ctx, remote.ID)
		switch {
		case err == nil:
			if local.DirtyState == localstore.DirtyStateClean && local.ServerRevision == remote.ServerRevision {
				continue
			}
			if local.DirtyState != localstore.DirtyStateClean && local.ServerRevision != remote.ServerRevision {
				alreadyConflicted := local.DirtyState == localstore.DirtyStateConflict
				if alreadyConflicted {
					if _, conflictErr := store.Conflict(ctx, local.ID); conflictErr == nil {
						continue
					} else if !errors.Is(conflictErr, localstore.ErrNotFound) {
						return 0, 0, conflictErr
					}
				}
				local.DirtyState = localstore.DirtyStateConflict
				if saveErr := store.SaveItemAndConflict(ctx, local, localstore.Conflict{
					ItemID:        local.ID,
					Reason:        "remote_changed",
					LocalRevision: local.ServerRevision,
					RemoteItem:    &remoteItem,
				}); saveErr != nil {
					return 0, 0, saveErr
				}
				if !alreadyConflicted {
					conflicts++
				}
				continue
			}
		case errors.Is(err, localstore.ErrNotFound):
		default:
			return 0, 0, err
		}

		if err = store.SaveItemAndClearConflict(ctx, remoteItem); err != nil {
			return 0, 0, err
		}
		pulled++
	}
	return pulled, conflicts, nil
}

func conflictFromPush(local localstore.Item, conflict clientapi.SyncConflict) (localstore.Conflict, error) {
	var remoteItem *localstore.Item
	if conflict.Remote != nil {
		remote, err := localItemFromSync(*conflict.Remote, localstore.DirtyStateClean)
		if err != nil {
			return localstore.Conflict{}, err
		}
		remoteItem = &remote
	}
	reason := conflict.Reason
	if reason == "" {
		reason = "revision_mismatch"
	}
	return localstore.Conflict{
		ItemID:        local.ID,
		Reason:        reason,
		LocalRevision: local.ServerRevision,
		RemoteItem:    remoteItem,
	}, nil
}

func localItemFromSync(item clientapi.SyncItem, dirtyState string) (localstore.Item, error) {
	payload, err := base64.StdEncoding.DecodeString(item.EncryptedPayload)
	if err != nil {
		return localstore.Item{}, fmt.Errorf("decode item payload %s: %w", item.ID, err)
	}
	nonce, err := base64.StdEncoding.DecodeString(item.PayloadNonce)
	if err != nil {
		return localstore.Item{}, fmt.Errorf("decode item nonce %s: %w", item.ID, err)
	}
	updatedAt := item.UpdatedAt
	if updatedAt.IsZero() {
		updatedAt = time.Now().UTC()
	}
	return localstore.Item{
		ID:               item.ID,
		ServerRevision:   item.ServerRevision,
		EncryptedPayload: payload,
		PayloadNonce:     nonce,
		PayloadVersion:   item.PayloadVersion,
		DeletedAt:        cloneTimePtr(item.DeletedAt),
		DirtyState:       dirtyState,
		UpdatedAt:        updatedAt.UTC(),
	}, nil
}

func maxSyncItemRevision(items []clientapi.SyncItem) int64 {
	var maxRevision int64
	for _, item := range items {
		if item.ServerRevision > maxRevision {
			maxRevision = item.ServerRevision
		}
	}
	return maxRevision
}

func cloneTimePtr(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	cloned := value.UTC()
	return &cloned
}
