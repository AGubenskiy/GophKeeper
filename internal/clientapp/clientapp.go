package clientapp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/AGubenskiy/GophKeeper/internal/buildinfo"
	"github.com/AGubenskiy/GophKeeper/internal/clientapi"
	"github.com/AGubenskiy/GophKeeper/internal/clientcrypto"
	"github.com/AGubenskiy/GophKeeper/internal/cryptoutil"
	"github.com/AGubenskiy/GophKeeper/internal/localstore"
	"github.com/AGubenskiy/GophKeeper/internal/prompt"
	"github.com/google/uuid"
	"github.com/spf13/cobra"
)

const defaultDBFileName = "client.db"

// Run executes the CLI client and returns a process exit code.
func Run(args []string, stdout, stderr io.Writer, info buildinfo.Info) int {
	deps := defaultDependencies(stdout, stderr, info)
	return run(args, deps)
}

type dependencies struct {
	stdout           io.Writer
	stderr           io.Writer
	info             buildinfo.Info
	storeFactory     func(string) (clientStore, error)
	apiFactory       func(string) (authAPI, error)
	prompter         prompt.SecretPrompter
	deriveAuthSecret func([]byte, string, string) ([]byte, error)
	deriveVaultKey   func([]byte, []byte, cryptoutil.KDFParams) ([]byte, error)
	newClientID      func() string
	newItemID        func() string
	now              func() time.Time
}

type clientStore interface {
	SaveProfile(context.Context, localstore.Profile) error
	Profile(context.Context) (localstore.Profile, error)
	SaveSession(context.Context, localstore.Session) error
	Session(context.Context) (localstore.Session, error)
	ClearSession(context.Context) error
	Status(context.Context) (localstore.Status, error)
	SaveItem(context.Context, localstore.Item) error
	Item(context.Context, string) (localstore.Item, error)
	ListItems(context.Context, bool) ([]localstore.Item, error)
	DeleteItem(context.Context, string, time.Time) error
	SaveItemAndClearConflict(context.Context, localstore.Item) error
	SaveItemAndConflict(context.Context, localstore.Item, localstore.Conflict) error
	SaveConflict(context.Context, localstore.Conflict) error
	Conflict(context.Context, string) (localstore.Conflict, error)
	ListConflicts(context.Context) ([]localstore.Conflict, error)
	ClearConflict(context.Context, string) error
	Close() error
}

type authAPI interface {
	Register(context.Context, clientapi.CredentialsRequest) (clientapi.Session, error)
	Login(context.Context, clientapi.CredentialsRequest) (clientapi.Session, error)
	Refresh(context.Context, string) (clientapi.Session, error)
	Logout(context.Context, string) error
	PushChanges(context.Context, string, []clientapi.PushItem) (clientapi.PushResponse, error)
	PullChanges(context.Context, string, int64) (clientapi.Changes, error)
}

type rootOptions struct {
	dataDir string
}

type authOptions struct {
	serverURL string
	login     string
}

func defaultDependencies(stdout, stderr io.Writer, info buildinfo.Info) dependencies {
	if stdout == nil {
		stdout = io.Discard
	}
	if stderr == nil {
		stderr = io.Discard
	}

	return dependencies{
		stdout: stdout,
		stderr: stderr,
		info:   info,
		storeFactory: func(path string) (clientStore, error) {
			return localstore.Open(path)
		},
		apiFactory: func(serverURL string) (authAPI, error) {
			return clientapi.New(serverURL, &http.Client{Timeout: 10 * time.Second})
		},
		prompter:         prompt.NewTerminalPrompter(),
		deriveAuthSecret: clientcrypto.DeriveAuthSecret,
		deriveVaultKey:   clientcrypto.DeriveVaultKey,
		newClientID: func() string {
			return uuid.NewString()
		},
		newItemID: func() string {
			return uuid.NewString()
		},
		now: time.Now,
	}
}

func run(args []string, deps dependencies) int {
	command := newRootCommand(deps)
	command.SetArgs(args)
	if err := command.Execute(); err != nil {
		_, _ = fmt.Fprintf(deps.stderr, "Error: %s\n", commandErrorMessage(err))
		return 1
	}
	return 0
}

func commandErrorMessage(err error) string {
	if err == nil {
		return ""
	}

	var apiErr *clientapi.Error
	if errors.As(err, &apiErr) {
		return formatAPIError(apiErr)
	}
	return err.Error()
}

func formatAPIError(err *clientapi.Error) string {
	if err == nil {
		return ""
	}

	switch err.Code {
	case "invalid_credentials":
		return appendRequestID("invalid login or master password", err.RequestID)
	case "invalid_refresh_token", "unauthorized":
		return appendRequestID("session expired or unauthorized; run login again", err.RequestID)
	case "auth_unavailable", "sync_unavailable":
		return appendRequestID("server feature is not configured; check server database and token settings", err.RequestID)
	}

	message := strings.TrimSpace(err.Message)
	if message == "" {
		message = http.StatusText(err.StatusCode)
	}
	if message == "" {
		message = "server returned an error"
	}

	if strings.TrimSpace(err.Code) != "" {
		message = fmt.Sprintf("%s: %s", err.Code, message)
	}
	if err.StatusCode > 0 {
		message = fmt.Sprintf("server returned HTTP %d: %s", err.StatusCode, message)
	}
	return appendRequestID(message, err.RequestID)
}

func appendRequestID(message, requestID string) string {
	requestID = strings.TrimSpace(requestID)
	if requestID == "" {
		return message
	}
	return fmt.Sprintf("%s (request id: %s)", message, requestID)
}

func newRootCommand(deps dependencies) *cobra.Command {
	rootOpts := rootOptions{dataDir: defaultDataDir()}

	root := &cobra.Command{
		Use:           "gk",
		Short:         "GophKeeper CLI client",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.SetOut(deps.stdout)
	root.SetErr(deps.stderr)
	root.PersistentFlags().StringVar(&rootOpts.dataDir, "data-dir", rootOpts.dataDir, "client data directory")

	root.AddCommand(newVersionCommand(deps))
	root.AddCommand(newRegisterCommand(deps, &rootOpts))
	root.AddCommand(newLoginCommand(deps, &rootOpts))
	root.AddCommand(newLogoutCommand(deps, &rootOpts))
	root.AddCommand(newStatusCommand(deps, &rootOpts))
	root.AddCommand(newAddCommand(deps, &rootOpts))
	root.AddCommand(newListCommand(deps, &rootOpts))
	root.AddCommand(newShowCommand(deps, &rootOpts))
	root.AddCommand(newEditCommand(deps, &rootOpts))
	root.AddCommand(newDeleteCommand(deps, &rootOpts))
	root.AddCommand(newSyncCommand(deps, &rootOpts))
	root.AddCommand(newConflictCommand(deps, &rootOpts))

	return root
}

func newVersionCommand(deps dependencies) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print build metadata",
		Args:  cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			return deps.info.Print(deps.stdout)
		},
	}
}

func newRegisterCommand(deps dependencies, rootOpts *rootOptions) *cobra.Command {
	var opts authOptions
	command := &cobra.Command{
		Use:   "register",
		Short: "Register a user and create a local profile",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if strings.TrimSpace(opts.serverURL) == "" {
				return errors.New("--server is required")
			}
			if strings.TrimSpace(opts.login) == "" {
				return errors.New("--login is required")
			}

			store, err := openStore(rootOpts, deps)
			if err != nil {
				return err
			}
			defer closeStore(store)

			clientID := deps.newClientID()
			session, err := authenticate(cmd.Context(), deps, opts, true, clientID)
			if err != nil {
				return err
			}
			if err = saveSession(cmd.Context(), store, opts.serverURL, session, clientID); err != nil {
				return err
			}

			_, _ = fmt.Fprintf(deps.stdout, "Registered %s on %s\n", session.Login, normalizeDisplayURL(opts.serverURL))
			return nil
		},
	}
	command.Flags().StringVar(&opts.serverURL, "server", "", "server URL")
	command.Flags().StringVar(&opts.login, "login", "", "user login")
	return command
}

func newLoginCommand(deps dependencies, rootOpts *rootOptions) *cobra.Command {
	var opts authOptions
	command := &cobra.Command{
		Use:   "login",
		Short: "Authenticate and store a local session",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			store, err := openStore(rootOpts, deps)
			if err != nil {
				return err
			}
			defer closeStore(store)

			opts, err = resolveLoginOptions(cmd.Context(), store, opts)
			if err != nil {
				return err
			}

			profile, profileErr := store.Profile(cmd.Context())
			clientID := deps.newClientID()
			if profileErr == nil && profile.ClientID != "" {
				clientID = profile.ClientID
			}

			session, err := authenticate(cmd.Context(), deps, opts, false, clientID)
			if err != nil {
				return err
			}
			if err = saveSession(cmd.Context(), store, opts.serverURL, session, clientID); err != nil {
				return err
			}

			_, _ = fmt.Fprintf(deps.stdout, "Logged in as %s on %s\n", session.Login, normalizeDisplayURL(opts.serverURL))
			return nil
		},
	}
	command.Flags().StringVar(&opts.serverURL, "server", "", "server URL")
	command.Flags().StringVar(&opts.login, "login", "", "user login")
	return command
}

func newLogoutCommand(deps dependencies, rootOpts *rootOptions) *cobra.Command {
	return &cobra.Command{
		Use:   "logout",
		Short: "Revoke the refresh token and clear the local session",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			store, err := openStore(rootOpts, deps)
			if err != nil {
				return err
			}
			defer closeStore(store)

			profile, err := store.Profile(cmd.Context())
			if err != nil {
				if errors.Is(err, localstore.ErrNotFound) {
					return errors.New("local profile not found; run login first")
				}
				return fmt.Errorf("load profile: %w", err)
			}
			session, err := store.Session(cmd.Context())
			if err != nil {
				if errors.Is(err, localstore.ErrNotFound) {
					return errors.New("local session not found; run login first")
				}
				return fmt.Errorf("load session: %w", err)
			}
			api, err := deps.apiFactory(profile.ServerURL)
			if err != nil {
				return err
			}
			if err = api.Logout(cmd.Context(), session.RefreshToken); err != nil {
				return err
			}
			if err = store.ClearSession(cmd.Context()); err != nil {
				return err
			}

			_, _ = fmt.Fprintln(deps.stdout, "Logged out")
			return nil
		},
	}
}

func newStatusCommand(deps dependencies, rootOpts *rootOptions) *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show local profile and synchronization status",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			store, err := openStore(rootOpts, deps)
			if err != nil {
				return err
			}
			defer closeStore(store)

			status, err := store.Status(cmd.Context())
			if err != nil {
				return err
			}
			printStatus(deps.stdout, status)
			return nil
		},
	}
}

func authenticate(ctx context.Context, deps dependencies, opts authOptions, register bool, clientID string) (clientapi.Session, error) {
	masterPassword, err := deps.prompter.ReadSecret("Master password")
	if err != nil {
		return clientapi.Session{}, err
	}
	defer cryptoutil.Zero(masterPassword)

	authSecret, err := deps.deriveAuthSecret(masterPassword, opts.serverURL, opts.login)
	if err != nil {
		return clientapi.Session{}, err
	}
	defer cryptoutil.Zero(authSecret)

	if clientID == "" {
		clientID = deps.newClientID()
	}
	api, err := deps.apiFactory(opts.serverURL)
	if err != nil {
		return clientapi.Session{}, err
	}

	request := clientapi.NewCredentialsRequest(opts.login, authSecret, clientID)
	if register {
		return api.Register(ctx, request)
	}
	return api.Login(ctx, request)
}

func saveSession(ctx context.Context, store clientStore, serverURL string, session clientapi.Session, clientID string) error {
	authSalt, err := session.AuthSaltBytes()
	if err != nil {
		return fmt.Errorf("decode auth salt: %w", err)
	}
	vaultSalt, err := session.VaultSaltBytes()
	if err != nil {
		return fmt.Errorf("decode vault salt: %w", err)
	}
	if session.KDFParams == nil {
		return errors.New("server response is missing kdf params")
	}
	kdfParams, err := cryptoutil.MarshalKDFParams(*session.KDFParams)
	if err != nil {
		return err
	}

	if err = store.SaveProfile(ctx, localstore.Profile{
		ServerURL: serverURL,
		UserID:    session.UserID,
		Login:     session.Login,
		ClientID:  clientID,
		AuthSalt:  authSalt,
		VaultSalt: vaultSalt,
		KDFParams: kdfParams,
	}); err != nil {
		return err
	}

	return store.SaveSession(ctx, localstore.Session{
		AccessToken:      session.AccessToken,
		AccessExpiresAt:  session.AccessExpiresAt,
		RefreshToken:     session.RefreshToken,
		RefreshExpiresAt: session.RefreshExpiresAt,
	})
}

func resolveLoginOptions(ctx context.Context, store clientStore, opts authOptions) (authOptions, error) {
	if strings.TrimSpace(opts.serverURL) != "" && strings.TrimSpace(opts.login) != "" {
		return opts, nil
	}

	profile, err := store.Profile(ctx)
	if err != nil {
		if errors.Is(err, localstore.ErrNotFound) {
			return opts, errors.New("--server and --login are required for first login")
		}
		return opts, err
	}
	if strings.TrimSpace(opts.serverURL) == "" {
		opts.serverURL = profile.ServerURL
	}
	if strings.TrimSpace(opts.login) == "" {
		opts.login = profile.Login
	}
	return opts, nil
}

func openStore(rootOpts *rootOptions, deps dependencies) (clientStore, error) {
	path := filepath.Join(rootOpts.dataDir, defaultDBFileName)
	return deps.storeFactory(path)
}

func closeStore(store clientStore) {
	if store != nil {
		_ = store.Close()
	}
}

func printStatus(w io.Writer, status localstore.Status) {
	if !status.HasProfile {
		_, _ = fmt.Fprintln(w, "Profile: none")
		return
	}

	_, _ = fmt.Fprintf(w, "Profile: %s @ %s\n", status.Login, normalizeDisplayURL(status.ServerURL))
	_, _ = fmt.Fprintf(w, "User ID: %s\n", status.UserID)
	_, _ = fmt.Fprintf(w, "Client ID: %s\n", status.ClientID)
	if status.HasSession {
		_, _ = fmt.Fprintln(w, "Session: active")
	} else {
		_, _ = fmt.Fprintln(w, "Session: none")
	}
	_, _ = fmt.Fprintf(w, "Last revision: %d\n", status.LastRevision)
	_, _ = fmt.Fprintf(w, "Local items: %d (dirty: %d)\n", status.ItemCount, status.DirtyCount)
	if status.ConflictCount > 0 {
		_, _ = fmt.Fprintf(w, "Conflicts: %d\n", status.ConflictCount)
	}
}

func normalizeDisplayURL(value string) string {
	return strings.TrimRight(value, "/")
}

func defaultDataDir() string {
	dir, err := os.UserConfigDir()
	if err != nil || dir == "" {
		return filepath.Join(".", ".gophkeeper")
	}
	return filepath.Join(dir, "gophkeeper")
}
