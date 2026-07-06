package clientapp

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"mime"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/AGubenskiy/GophKeeper/internal/cryptoutil"
	"github.com/AGubenskiy/GophKeeper/internal/localstore"
	"github.com/AGubenskiy/GophKeeper/internal/vaultitem"
	"github.com/spf13/cobra"
)

type addItemOptions struct {
	title     string
	metadata  []string
	login     string
	text      string
	number    string
	holder    string
	expiry    string
	path      string
	mediaType string
	promptCVV bool
}

type listOptions struct {
	kind string
}

type showOptions struct {
	reveal     bool
	exportPath string
}

type editOptions struct {
	title           string
	metadata        []string
	replaceMetadata bool
	login           string
	text            string
	number          string
	holder          string
	expiry          string
	path            string
	mediaType       string
	promptPassword  bool
	promptText      bool
	promptCVV       bool
}

type unlockedVault struct {
	profile localstore.Profile
	key     []byte
}

func newAddCommand(deps dependencies, rootOpts *rootOptions) *cobra.Command {
	command := &cobra.Command{
		Use:   "add",
		Short: "Add an encrypted vault item",
	}
	command.AddCommand(newAddPasswordCommand(deps, rootOpts))
	command.AddCommand(newAddTextCommand(deps, rootOpts))
	command.AddCommand(newAddCardCommand(deps, rootOpts))
	command.AddCommand(newAddFileCommand(deps, rootOpts))
	return command
}

func newAddPasswordCommand(deps dependencies, rootOpts *rootOptions) *cobra.Command {
	var opts addItemOptions
	command := &cobra.Command{
		Use:   "password",
		Short: "Add a login/password item",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if strings.TrimSpace(opts.title) == "" {
				return errors.New("--title is required")
			}

			password, err := readRequiredSecret(deps, "Password")
			if err != nil {
				return err
			}
			defer cryptoutil.Zero(password)

			metadata, err := parseMetadata(opts.metadata)
			if err != nil {
				return err
			}
			payload := vaultitem.NewPassword(opts.title, opts.login, password, metadata)
			return addVaultPayload(cmd.Context(), deps, rootOpts, payload)
		},
	}
	addCommonItemFlags(command, &opts)
	command.Flags().StringVar(&opts.login, "login", "", "item login")
	return command
}

func newAddTextCommand(deps dependencies, rootOpts *rootOptions) *cobra.Command {
	var opts addItemOptions
	command := &cobra.Command{
		Use:   "text",
		Short: "Add a text item",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if strings.TrimSpace(opts.title) == "" {
				return errors.New("--title is required")
			}

			text := []byte(opts.text)
			if strings.TrimSpace(opts.text) == "" {
				var err error
				text, err = readRequiredSecret(deps, "Text")
				if err != nil {
					return err
				}
				defer cryptoutil.Zero(text)
			}

			metadata, err := parseMetadata(opts.metadata)
			if err != nil {
				return err
			}
			payload := vaultitem.NewText(opts.title, text, metadata)
			return addVaultPayload(cmd.Context(), deps, rootOpts, payload)
		},
	}
	addCommonItemFlags(command, &opts)
	command.Flags().StringVar(&opts.text, "text", "", "item text")
	return command
}

func newAddCardCommand(deps dependencies, rootOpts *rootOptions) *cobra.Command {
	var opts addItemOptions
	command := &cobra.Command{
		Use:   "card",
		Short: "Add a bank card item",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if strings.TrimSpace(opts.title) == "" {
				return errors.New("--title is required")
			}
			if strings.TrimSpace(opts.number) == "" {
				return errors.New("--number is required")
			}
			if strings.TrimSpace(opts.expiry) == "" {
				return errors.New("--expiry is required")
			}

			var cvv []byte
			if opts.promptCVV {
				var err error
				cvv, err = readRequiredSecret(deps, "CVV")
				if err != nil {
					return err
				}
				defer cryptoutil.Zero(cvv)
			}

			metadata, err := parseMetadata(opts.metadata)
			if err != nil {
				return err
			}
			payload := vaultitem.NewCard(opts.title, opts.number, opts.holder, opts.expiry, cvv, metadata)
			return addVaultPayload(cmd.Context(), deps, rootOpts, payload)
		},
	}
	addCommonItemFlags(command, &opts)
	command.Flags().StringVar(&opts.number, "number", "", "card number")
	command.Flags().StringVar(&opts.holder, "holder", "", "card holder")
	command.Flags().StringVar(&opts.expiry, "expiry", "", "card expiry")
	command.Flags().BoolVar(&opts.promptCVV, "prompt-cvv", false, "prompt for card cvv")
	return command
}

func newAddFileCommand(deps dependencies, rootOpts *rootOptions) *cobra.Command {
	var opts addItemOptions
	command := &cobra.Command{
		Use:   "file",
		Short: "Add a file item",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if strings.TrimSpace(opts.title) == "" {
				return errors.New("--title is required")
			}
			if strings.TrimSpace(opts.path) == "" {
				return errors.New("--path is required")
			}

			content, err := os.ReadFile(opts.path)
			if err != nil {
				return fmt.Errorf("read file: %w", err)
			}
			metadata, err := parseMetadata(opts.metadata)
			if err != nil {
				return err
			}
			payload := vaultitem.NewFile(opts.title, opts.path, resolveMediaType(opts.path, opts.mediaType), content, metadata)
			return addVaultPayload(cmd.Context(), deps, rootOpts, payload)
		},
	}
	addCommonItemFlags(command, &opts)
	command.Flags().StringVar(&opts.path, "path", "", "file path")
	command.Flags().StringVar(&opts.mediaType, "media-type", "", "file media type")
	return command
}

func newListCommand(deps dependencies, rootOpts *rootOptions) *cobra.Command {
	var opts listOptions
	command := &cobra.Command{
		Use:   "list",
		Short: "List encrypted vault items",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			var kindFilter vaultitem.Kind
			if strings.TrimSpace(opts.kind) != "" {
				parsed, err := parseKind(opts.kind)
				if err != nil {
					return err
				}
				kindFilter = parsed
			}

			store, err := openStore(rootOpts, deps)
			if err != nil {
				return err
			}
			defer closeStore(store)

			vault, err := unlockVault(cmd.Context(), store, deps)
			if err != nil {
				return err
			}
			defer vault.Close()

			items, err := store.ListItems(cmd.Context(), false)
			if err != nil {
				return err
			}
			return printVaultList(deps.stdout, vault, items, kindFilter)
		},
	}
	command.Flags().StringVar(&opts.kind, "kind", "", "filter by kind: password, text, card, file")
	return command
}

func newShowCommand(deps dependencies, rootOpts *rootOptions) *cobra.Command {
	var opts showOptions
	command := &cobra.Command{
		Use:   "show ITEM_ID",
		Short: "Show one encrypted vault item",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := openStore(rootOpts, deps)
			if err != nil {
				return err
			}
			defer closeStore(store)

			vault, err := unlockVault(cmd.Context(), store, deps)
			if err != nil {
				return err
			}
			defer vault.Close()

			itemID := args[0]
			item, err := store.Item(cmd.Context(), itemID)
			if err != nil {
				return itemError(itemID, err)
			}
			if item.DeletedAt != nil {
				return fmt.Errorf("item %q is deleted", itemID)
			}

			payload, err := decryptLocalItem(vault, item)
			if err != nil {
				return err
			}
			return printVaultItem(deps.stdout, payload, opts)
		},
	}
	command.Flags().BoolVar(&opts.reveal, "reveal", false, "reveal masked card values")
	command.Flags().StringVar(&opts.exportPath, "export", "", "export file item content to path")
	return command
}

func newEditCommand(deps dependencies, rootOpts *rootOptions) *cobra.Command {
	var opts editOptions
	command := &cobra.Command{
		Use:   "edit ITEM_ID",
		Short: "Edit one encrypted vault item",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := openStore(rootOpts, deps)
			if err != nil {
				return err
			}
			defer closeStore(store)

			vault, err := unlockVault(cmd.Context(), store, deps)
			if err != nil {
				return err
			}
			defer vault.Close()

			itemID := args[0]
			item, err := store.Item(cmd.Context(), itemID)
			if err != nil {
				return itemError(itemID, err)
			}
			if item.DeletedAt != nil {
				return fmt.Errorf("item %q is deleted", itemID)
			}

			payload, err := decryptLocalItem(vault, item)
			if err != nil {
				return err
			}
			changed, err := applyPayloadEdit(cmd, deps, &payload, opts)
			if err != nil {
				return err
			}
			if !changed {
				return errors.New("no changes requested")
			}
			if err = saveExistingVaultPayload(cmd.Context(), deps, store, vault, item, payload); err != nil {
				return err
			}

			_, _ = fmt.Fprintf(deps.stdout, "Updated %s %s\n", payload.Kind, item.ID)
			return nil
		},
	}
	command.Flags().StringVar(&opts.title, "title", "", "new title")
	command.Flags().StringArrayVar(&opts.metadata, "meta", nil, "metadata key=value")
	command.Flags().BoolVar(&opts.replaceMetadata, "replace-meta", false, "replace metadata instead of merging")
	command.Flags().StringVar(&opts.login, "login", "", "new password item login")
	command.Flags().StringVar(&opts.text, "text", "", "new text item value")
	command.Flags().StringVar(&opts.number, "number", "", "new card number")
	command.Flags().StringVar(&opts.holder, "holder", "", "new card holder")
	command.Flags().StringVar(&opts.expiry, "expiry", "", "new card expiry")
	command.Flags().StringVar(&opts.path, "path", "", "new file path")
	command.Flags().StringVar(&opts.mediaType, "media-type", "", "new file media type")
	command.Flags().BoolVar(&opts.promptPassword, "password", false, "prompt for a new password value")
	command.Flags().BoolVar(&opts.promptText, "prompt-text", false, "prompt for a new text value")
	command.Flags().BoolVar(&opts.promptCVV, "prompt-cvv", false, "prompt for a new card cvv")
	return command
}

func newDeleteCommand(deps dependencies, rootOpts *rootOptions) *cobra.Command {
	return &cobra.Command{
		Use:   "delete ITEM_ID",
		Short: "Delete one local vault item",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := openStore(rootOpts, deps)
			if err != nil {
				return err
			}
			defer closeStore(store)

			if err = store.DeleteItem(cmd.Context(), args[0], deps.now().UTC()); err != nil {
				return itemError(args[0], err)
			}
			_, _ = fmt.Fprintf(deps.stdout, "Deleted %s\n", args[0])
			return nil
		},
	}
}

func addCommonItemFlags(command *cobra.Command, opts *addItemOptions) {
	command.Flags().StringVar(&opts.title, "title", "", "item title")
	command.Flags().StringArrayVar(&opts.metadata, "meta", nil, "metadata key=value")
}

func addVaultPayload(ctx context.Context, deps dependencies, rootOpts *rootOptions, payload vaultitem.Payload) error {
	store, err := openStore(rootOpts, deps)
	if err != nil {
		return err
	}
	defer closeStore(store)

	vault, err := unlockVault(ctx, store, deps)
	if err != nil {
		return err
	}
	defer vault.Close()

	itemID := deps.newItemID()
	if strings.TrimSpace(itemID) == "" {
		return errors.New("generated item id is empty")
	}

	ciphertext, nonce, err := vaultitem.Encrypt(vault.key, vault.profile.UserID, itemID, payload)
	if err != nil {
		return err
	}

	if err = store.SaveItem(ctx, localstore.Item{
		ID:               itemID,
		EncryptedPayload: ciphertext,
		PayloadNonce:     nonce,
		PayloadVersion:   vaultitem.PayloadVersion,
		DirtyState:       localstore.DirtyStateUpsert,
		UpdatedAt:        deps.now().UTC(),
	}); err != nil {
		return err
	}

	_, _ = fmt.Fprintf(deps.stdout, "Added %s %s\n", payload.Kind, itemID)
	return nil
}

func saveExistingVaultPayload(ctx context.Context, deps dependencies, store clientStore, vault unlockedVault, item localstore.Item, payload vaultitem.Payload) error {
	ciphertext, nonce, err := vaultitem.Encrypt(vault.key, vault.profile.UserID, item.ID, payload)
	if err != nil {
		return err
	}
	return store.SaveItem(ctx, localstore.Item{
		ID:               item.ID,
		ServerRevision:   item.ServerRevision,
		EncryptedPayload: ciphertext,
		PayloadNonce:     nonce,
		PayloadVersion:   vaultitem.PayloadVersion,
		DirtyState:       localstore.DirtyStateUpsert,
		UpdatedAt:        deps.now().UTC(),
	})
}

func itemError(itemID string, err error) error {
	if errors.Is(err, localstore.ErrNotFound) {
		return fmt.Errorf("item %q not found", itemID)
	}
	return err
}

func unlockVault(ctx context.Context, store clientStore, deps dependencies) (unlockedVault, error) {
	profile, err := store.Profile(ctx)
	if err != nil {
		if errors.Is(err, localstore.ErrNotFound) {
			return unlockedVault{}, errors.New("local profile not found; run login first")
		}
		return unlockedVault{}, err
	}
	params, err := cryptoutil.ParseKDFParams(profile.KDFParams)
	if err != nil {
		return unlockedVault{}, fmt.Errorf("parse profile kdf params: %w", err)
	}

	masterPassword, err := deps.prompter.ReadSecret("Master password")
	if err != nil {
		return unlockedVault{}, err
	}
	defer cryptoutil.Zero(masterPassword)

	key, err := deps.deriveVaultKey(masterPassword, profile.VaultSalt, params)
	if err != nil {
		return unlockedVault{}, err
	}
	return unlockedVault{profile: profile, key: key}, nil
}

func (v unlockedVault) Close() {
	cryptoutil.Zero(v.key)
}

func decryptLocalItem(vault unlockedVault, item localstore.Item) (vaultitem.Payload, error) {
	if item.PayloadVersion != vaultitem.PayloadVersion {
		return vaultitem.Payload{}, fmt.Errorf("unsupported item payload version %d", item.PayloadVersion)
	}
	payload, err := vaultitem.Decrypt(vault.key, vault.profile.UserID, item.ID, item.EncryptedPayload, item.PayloadNonce)
	if err != nil {
		return vaultitem.Payload{}, fmt.Errorf("decrypt item %s: %w", item.ID, err)
	}
	return payload, nil
}

func printVaultList(w io.Writer, vault unlockedVault, items []localstore.Item, kindFilter vaultitem.Kind) error {
	rows := make([]struct {
		id      string
		kind    vaultitem.Kind
		title   string
		updated string
	}, 0, len(items))

	for _, item := range items {
		payload, err := decryptLocalItem(vault, item)
		if err != nil {
			return err
		}
		if kindFilter != "" && payload.Kind != kindFilter {
			continue
		}
		rows = append(rows, struct {
			id      string
			kind    vaultitem.Kind
			title   string
			updated string
		}{
			id:      item.ID,
			kind:    payload.Kind,
			title:   payload.Title,
			updated: item.UpdatedAt.Format("2006-01-02 15:04:05"),
		})
	}

	if len(rows) == 0 {
		_, _ = fmt.Fprintln(w, "No items")
		return nil
	}

	_, _ = fmt.Fprintf(w, "%-36s  %-8s  %-32s  %s\n", "ID", "KIND", "TITLE", "UPDATED")
	for _, row := range rows {
		_, _ = fmt.Fprintf(w, "%-36s  %-8s  %-32s  %s\n", row.id, row.kind, truncate(row.title, 32), row.updated)
	}
	return nil
}

func printVaultItem(w io.Writer, payload vaultitem.Payload, opts showOptions) error {
	_, _ = fmt.Fprintf(w, "Kind: %s\n", payload.Kind)
	_, _ = fmt.Fprintf(w, "Title: %s\n", payload.Title)
	printMetadata(w, payload.Metadata)

	switch payload.Kind {
	case vaultitem.KindPassword:
		_, _ = fmt.Fprintf(w, "Login: %s\n", payload.Fields[vaultitem.FieldLogin])
		_, _ = fmt.Fprintf(w, "Password: %s\n", payload.Fields[vaultitem.FieldPassword])
	case vaultitem.KindText:
		_, _ = fmt.Fprintf(w, "Text:\n%s\n", payload.Fields[vaultitem.FieldText])
	case vaultitem.KindCard:
		number := payload.Fields[vaultitem.FieldCardNumber]
		cvv := payload.Fields[vaultitem.FieldCardCVV]
		if !opts.reveal {
			number = maskCardNumber(number)
			if cvv != "" {
				cvv = "***"
			}
		}
		_, _ = fmt.Fprintf(w, "Number: %s\n", number)
		_, _ = fmt.Fprintf(w, "Holder: %s\n", payload.Fields[vaultitem.FieldCardHolder])
		_, _ = fmt.Fprintf(w, "Expiry: %s\n", payload.Fields[vaultitem.FieldCardExpiry])
		if cvv != "" {
			_, _ = fmt.Fprintf(w, "CVV: %s\n", cvv)
		}
	case vaultitem.KindFile:
		return printFilePayload(w, payload, opts.exportPath)
	default:
		return fmt.Errorf("unsupported item kind %q", payload.Kind)
	}
	return nil
}

func printFilePayload(w io.Writer, payload vaultitem.Payload, exportPath string) error {
	data, err := base64.StdEncoding.DecodeString(payload.Fields[vaultitem.FieldFileDataBase64])
	if err != nil {
		return fmt.Errorf("decode file content: %w", err)
	}

	_, _ = fmt.Fprintf(w, "File name: %s\n", payload.Fields[vaultitem.FieldFileName])
	_, _ = fmt.Fprintf(w, "Media type: %s\n", payload.Fields[vaultitem.FieldFileMediaType])
	_, _ = fmt.Fprintf(w, "Size: %d bytes\n", len(data))
	if strings.TrimSpace(exportPath) == "" {
		return nil
	}
	if err = os.WriteFile(exportPath, data, 0o600); err != nil {
		return fmt.Errorf("export file: %w", err)
	}
	_, _ = fmt.Fprintf(w, "Exported: %s\n", exportPath)
	return nil
}

func applyPayloadEdit(cmd *cobra.Command, deps dependencies, payload *vaultitem.Payload, opts editOptions) (bool, error) {
	changed := false

	if cmd.Flags().Changed("title") {
		payload.Title = opts.title
		changed = true
	}
	if cmd.Flags().Changed("meta") || opts.replaceMetadata {
		metadata, err := parseMetadata(opts.metadata)
		if err != nil {
			return false, err
		}
		if opts.replaceMetadata {
			payload.Metadata = metadata
		} else {
			payload.Metadata = mergeMetadata(payload.Metadata, metadata)
		}
		changed = true
	}

	switch payload.Kind {
	case vaultitem.KindPassword:
		if cmd.Flags().Changed("login") {
			setOptionalField(payload.Fields, vaultitem.FieldLogin, opts.login)
			changed = true
		}
		if opts.promptPassword {
			password, err := readRequiredSecret(deps, "Password")
			if err != nil {
				return false, err
			}
			defer cryptoutil.Zero(password)
			payload.Fields[vaultitem.FieldPassword] = string(password)
			changed = true
		}
	case vaultitem.KindText:
		if cmd.Flags().Changed("text") {
			payload.Fields[vaultitem.FieldText] = opts.text
			changed = true
		}
		if opts.promptText {
			text, err := readRequiredSecret(deps, "Text")
			if err != nil {
				return false, err
			}
			defer cryptoutil.Zero(text)
			payload.Fields[vaultitem.FieldText] = string(text)
			changed = true
		}
	case vaultitem.KindCard:
		if cmd.Flags().Changed("number") {
			payload.Fields[vaultitem.FieldCardNumber] = strings.TrimSpace(opts.number)
			changed = true
		}
		if cmd.Flags().Changed("holder") {
			setOptionalField(payload.Fields, vaultitem.FieldCardHolder, opts.holder)
			changed = true
		}
		if cmd.Flags().Changed("expiry") {
			payload.Fields[vaultitem.FieldCardExpiry] = strings.TrimSpace(opts.expiry)
			changed = true
		}
		if opts.promptCVV {
			cvv, err := readRequiredSecret(deps, "CVV")
			if err != nil {
				return false, err
			}
			defer cryptoutil.Zero(cvv)
			payload.Fields[vaultitem.FieldCardCVV] = string(cvv)
			changed = true
		}
	case vaultitem.KindFile:
		if cmd.Flags().Changed("path") {
			content, err := os.ReadFile(opts.path)
			if err != nil {
				return false, fmt.Errorf("read file: %w", err)
			}
			payload.Fields[vaultitem.FieldFileName] = filepath.Base(opts.path)
			payload.Fields[vaultitem.FieldFileDataBase64] = base64.StdEncoding.EncodeToString(content)
			payload.Fields[vaultitem.FieldFileMediaType] = resolveMediaType(opts.path, opts.mediaType)
			changed = true
		}
		if cmd.Flags().Changed("media-type") && !cmd.Flags().Changed("path") {
			setOptionalField(payload.Fields, vaultitem.FieldFileMediaType, opts.mediaType)
			changed = true
		}
	default:
		return false, fmt.Errorf("unsupported item kind %q", payload.Kind)
	}

	if changed {
		payload.Version = vaultitem.PayloadVersion
		if payload.Fields == nil {
			payload.Fields = map[string]string{}
		}
		if err := payload.Validate(); err != nil {
			return false, err
		}
	}
	return changed, nil
}

func readRequiredSecret(deps dependencies, label string) ([]byte, error) {
	value, err := deps.prompter.ReadSecret(label)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(string(value)) == "" {
		cryptoutil.Zero(value)
		return nil, fmt.Errorf("%s is required", strings.ToLower(label))
	}
	return value, nil
}

func parseMetadata(values []string) (map[string]string, error) {
	if len(values) == 0 {
		return nil, nil
	}
	out := make(map[string]string, len(values))
	for _, raw := range values {
		key, value, ok := strings.Cut(raw, "=")
		if !ok {
			return nil, fmt.Errorf("metadata must use key=value: %q", raw)
		}
		key = strings.TrimSpace(key)
		if key == "" {
			return nil, errors.New("metadata key is required")
		}
		out[key] = value
	}
	return out, nil
}

func mergeMetadata(base, updates map[string]string) map[string]string {
	out := make(map[string]string, len(base)+len(updates))
	for key, value := range base {
		out[key] = value
	}
	for key, value := range updates {
		out[key] = value
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func parseKind(value string) (vaultitem.Kind, error) {
	switch vaultitem.Kind(strings.TrimSpace(value)) {
	case vaultitem.KindPassword:
		return vaultitem.KindPassword, nil
	case vaultitem.KindText:
		return vaultitem.KindText, nil
	case vaultitem.KindCard:
		return vaultitem.KindCard, nil
	case vaultitem.KindFile:
		return vaultitem.KindFile, nil
	default:
		return "", fmt.Errorf("unsupported item kind %q", value)
	}
}

func printMetadata(w io.Writer, metadata map[string]string) {
	if len(metadata) == 0 {
		return
	}
	keys := make([]string, 0, len(metadata))
	for key := range metadata {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	_, _ = fmt.Fprintln(w, "Metadata:")
	for _, key := range keys {
		_, _ = fmt.Fprintf(w, "  %s: %s\n", key, metadata[key])
	}
}

func resolveMediaType(path, explicit string) string {
	if strings.TrimSpace(explicit) != "" {
		return strings.TrimSpace(explicit)
	}
	if detected := mime.TypeByExtension(strings.ToLower(filepath.Ext(path))); detected != "" {
		return detected
	}
	return "application/octet-stream"
}

func maskCardNumber(number string) string {
	compact := strings.NewReplacer(" ", "", "-", "").Replace(number)
	if len(compact) <= 4 {
		return "****"
	}
	return "**** **** **** " + compact[len(compact)-4:]
}

func truncate(value string, max int) string {
	if len(value) <= max {
		return value
	}
	if max <= 3 {
		return value[:max]
	}
	return value[:max-3] + "..."
}

func setOptionalField(fields map[string]string, key, value string) {
	if strings.TrimSpace(value) == "" {
		delete(fields, key)
		return
	}
	fields[key] = strings.TrimSpace(value)
}
