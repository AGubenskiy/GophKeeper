package clientapp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"
	"time"

	"github.com/AGubenskiy/GophKeeper/internal/localstore"
	"github.com/spf13/cobra"
)

func newConflictCommand(deps dependencies, rootOpts *rootOptions) *cobra.Command {
	command := &cobra.Command{
		Use:   "conflict",
		Short: "Inspect and resolve synchronization conflicts",
	}
	command.AddCommand(newConflictListCommand(deps, rootOpts))
	command.AddCommand(newConflictKeepLocalCommand(deps, rootOpts))
	command.AddCommand(newConflictKeepRemoteCommand(deps, rootOpts))
	return command
}

func newConflictListCommand(deps dependencies, rootOpts *rootOptions) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List local synchronization conflicts",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			store, err := openStore(rootOpts, deps)
			if err != nil {
				return err
			}
			defer closeStore(store)

			conflicts, err := store.ListConflicts(cmd.Context())
			if err != nil {
				return err
			}
			printConflicts(deps.stdout, conflicts)
			return nil
		},
	}
}

func newConflictKeepLocalCommand(deps dependencies, rootOpts *rootOptions) *cobra.Command {
	return &cobra.Command{
		Use:   "keep-local ITEM_ID",
		Short: "Resolve a conflict by pushing the local item on next sync",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := openStore(rootOpts, deps)
			if err != nil {
				return err
			}
			defer closeStore(store)

			if err = keepLocalConflict(cmd.Context(), store, args[0], deps.now()); err != nil {
				return err
			}
			_, _ = fmt.Fprintf(deps.stdout, "Kept local %s\n", args[0])
			return nil
		},
	}
}

func newConflictKeepRemoteCommand(deps dependencies, rootOpts *rootOptions) *cobra.Command {
	return &cobra.Command{
		Use:   "keep-remote ITEM_ID",
		Short: "Resolve a conflict by accepting the remote item",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := openStore(rootOpts, deps)
			if err != nil {
				return err
			}
			defer closeStore(store)

			if err = keepRemoteConflict(cmd.Context(), store, args[0]); err != nil {
				return err
			}
			_, _ = fmt.Fprintf(deps.stdout, "Kept remote %s\n", args[0])
			return nil
		},
	}
}

func printConflicts(w io.Writer, conflicts []localstore.Conflict) {
	if len(conflicts) == 0 {
		_, _ = fmt.Fprintln(w, "No conflicts")
		return
	}
	_, _ = fmt.Fprintf(w, "%-36s  %-20s  %-10s  %-10s  %s\n", "ID", "REASON", "LOCAL_REV", "REMOTE_REV", "UPDATED")
	for _, conflict := range conflicts {
		_, _ = fmt.Fprintf(
			w,
			"%-36s  %-20s  %-10d  %-10s  %s\n",
			conflict.ItemID,
			truncate(conflict.Reason, 20),
			conflict.LocalRevision,
			remoteRevision(conflict),
			conflict.UpdatedAt.Format("2006-01-02 15:04:05"),
		)
	}
}

func keepLocalConflict(ctx context.Context, store clientStore, itemID string, now time.Time) error {
	conflict, err := store.Conflict(ctx, itemID)
	if err != nil {
		return conflictError(itemID, err)
	}
	item, err := store.Item(ctx, itemID)
	if err != nil {
		return itemError(itemID, err)
	}
	if item.DirtyState != localstore.DirtyStateConflict {
		return fmt.Errorf("item %q is not marked as conflict", itemID)
	}

	if conflict.RemoteItem != nil {
		item.ServerRevision = conflict.RemoteItem.ServerRevision
	} else {
		item.ServerRevision = 0
	}
	if item.DeletedAt != nil {
		item.DirtyState = localstore.DirtyStateDelete
	} else {
		item.DirtyState = localstore.DirtyStateUpsert
	}
	item.UpdatedAt = now.UTC()
	return store.SaveItemAndClearConflict(ctx, item)
}

func keepRemoteConflict(ctx context.Context, store clientStore, itemID string) error {
	conflict, err := store.Conflict(ctx, itemID)
	if err != nil {
		return conflictError(itemID, err)
	}
	if conflict.RemoteItem == nil {
		return errors.New("conflict has no remote item to keep")
	}

	remote := conflict.RemoteItem.Clone()
	remote.DirtyState = localstore.DirtyStateClean
	return store.SaveItemAndClearConflict(ctx, remote)
}

func conflictError(itemID string, err error) error {
	if errors.Is(err, localstore.ErrNotFound) {
		return fmt.Errorf("conflict for item %q not found; run `gk conflict list`", itemID)
	}
	return err
}

func remoteRevision(conflict localstore.Conflict) string {
	if conflict.RemoteItem == nil {
		return "-"
	}
	return strconv.FormatInt(conflict.RemoteItem.ServerRevision, 10)
}
