package serverapp

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/AGubenskiy/GophKeeper/internal/auth"
	"github.com/AGubenskiy/GophKeeper/internal/buildinfo"
	"github.com/AGubenskiy/GophKeeper/internal/config"
	"github.com/AGubenskiy/GophKeeper/internal/cryptoutil"
	"github.com/AGubenskiy/GophKeeper/internal/httpapi"
	"github.com/AGubenskiy/GophKeeper/internal/logger"
	"github.com/AGubenskiy/GophKeeper/internal/postgres"
	"github.com/AGubenskiy/GophKeeper/internal/syncsvc"
	"github.com/AGubenskiy/GophKeeper/internal/tokens"
	"github.com/AGubenskiy/GophKeeper/migrations"
	_ "github.com/jackc/pgx/v5/stdlib"
)

const usage = `Usage:
  gk-server [flags]
  gk-server version
  gk-server help

Flags:
  --access-token-secret value JWT access token signing secret, required when --database-dsn is set
  --access-token-ttl value    JWT access token lifetime (default "15m0s")
  --address value            HTTP listen address (default "localhost:8080")
  --database-dsn value       PostgreSQL connection string
  --log-level value          log level: debug, info, warn, or error (default "info")
  --refresh-token-ttl value   refresh token lifetime (default "720h0m0s")
  --shutdown-timeout value   graceful shutdown timeout (default "5s")

Environment:
  GOPHKEEPER_ACCESS_TOKEN_SECRET
  GOPHKEEPER_ACCESS_TOKEN_TTL
  GOPHKEEPER_DATABASE_DSN
  GOPHKEEPER_REFRESH_TOKEN_TTL
  GOPHKEEPER_SERVER_ADDRESS
  GOPHKEEPER_SERVER_LOG_LEVEL
  GOPHKEEPER_SERVER_SHUTDOWN_TIMEOUT
`

const readHeaderTimeout = 5 * time.Second

// Application owns the HTTP server lifecycle.
type Application struct {
	server          *http.Server
	shutdownTimeout time.Duration
	log             *slog.Logger
	info            buildinfo.Info
	closers         []io.Closer
	closeOnce       sync.Once
}

type applicationOptions struct {
	authService httpapi.AuthService
	syncService httpapi.SyncService
	verifier    httpapi.TokenVerifier
	closers     []io.Closer
}

// Option configures a server application.
type Option func(*applicationOptions)

// WithAuthService enables auth HTTP routes.
func WithAuthService(service httpapi.AuthService) Option {
	return func(options *applicationOptions) {
		options.authService = service
	}
}

// WithSyncService enables protected synchronization HTTP routes.
func WithSyncService(service httpapi.SyncService, verifier httpapi.TokenVerifier) Option {
	return func(options *applicationOptions) {
		options.syncService = service
		options.verifier = verifier
	}
}

// WithCloser registers a resource closed with the application.
func WithCloser(closer io.Closer) Option {
	return func(options *applicationOptions) {
		if closer != nil {
			options.closers = append(options.closers, closer)
		}
	}
}

// New creates a server application from runtime configuration.
func New(cfg config.Server, log *slog.Logger, info buildinfo.Info, opts ...Option) *Application {
	if log == nil {
		log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	info = info.Normalized()
	options := applicationOptions{}
	for _, opt := range opts {
		if opt != nil {
			opt(&options)
		}
	}

	return &Application{
		server: &http.Server{
			Addr:              cfg.Address,
			Handler:           httpapi.LoggingMiddleware(log)(NewHandlerWithAuth(info, options.authService, options.syncService, options.verifier)),
			ReadHeaderTimeout: readHeaderTimeout,
		},
		shutdownTimeout: cfg.ShutdownTimeout,
		log:             log,
		info:            info,
		closers:         options.closers,
	}
}

// Run executes the server application and returns a process exit code.
func Run(ctx context.Context, args []string, stdout, stderr io.Writer, info buildinfo.Info) int {
	if stdout == nil {
		stdout = io.Discard
	}
	if stderr == nil {
		stderr = io.Discard
	}

	if len(args) > 0 {
		switch args[0] {
		case "version":
			if len(args) != 1 {
				fmt.Fprintf(stderr, "gk-server version accepts no arguments\n\n")
				printUsage(stderr)
				return 2
			}
			if err := info.Print(stdout); err != nil {
				fmt.Fprintf(stderr, "print version: %v\n", err)
				return 1
			}
			return 0
		case "help":
			printUsage(stdout)
			return 0
		}
	}

	cfg, err := config.ParseServer(args, os.LookupEnv)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			printUsage(stdout)
			return 0
		}
		fmt.Fprintf(stderr, "configure server: %v\n\n", err)
		printUsage(stderr)
		return 2
	}

	log, err := logger.New(stderr, cfg.LogLevel)
	if err != nil {
		fmt.Fprintf(stderr, "configure logger: %v\n", err)
		return 2
	}

	services, err := buildRuntimeServices(ctx, cfg)
	if err != nil {
		fmt.Fprintf(stderr, "configure services: %v\n", err)
		return 2
	}

	options := make([]Option, 0, 2)
	if services.authService != nil {
		options = append(options, WithAuthService(services.authService))
	}
	if services.syncService != nil {
		options = append(options, WithSyncService(services.syncService, services.verifier))
	}
	if services.closer != nil {
		options = append(options, WithCloser(services.closer))
	}

	app := New(cfg, log, info, options...)
	defer app.Close()
	if err := app.Start(ctx); err != nil {
		fmt.Fprintf(stderr, "run server: %v\n", err)
		return 1
	}
	return 0
}

// Start listens on the configured address until the context is cancelled or the server fails.
func (a *Application) Start(ctx context.Context) error {
	listener, err := net.Listen("tcp", a.server.Addr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", a.server.Addr, err)
	}
	return a.Serve(ctx, listener)
}

// Serve serves HTTP traffic on listener and shuts down gracefully when ctx is cancelled.
func (a *Application) Serve(ctx context.Context, listener net.Listener) error {
	defer a.Close()

	if listener == nil {
		return errors.New("listener is nil")
	}
	if ctx == nil {
		ctx = context.Background()
	}

	a.log.Info(
		"server starting",
		slog.String("address", listener.Addr().String()),
		slog.String("version", a.info.Version),
		slog.String("build_date", a.info.Date),
		slog.String("commit", a.info.Commit),
	)

	errCh := make(chan error, 1)
	go func() {
		err := a.server.Serve(listener)
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
			return
		}
		errCh <- nil
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), a.shutdownTimeout)
		defer cancel()

		a.log.Info("server stopping")
		if err := a.server.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("shutdown server: %w", err)
		}
		if err := <-errCh; err != nil {
			return fmt.Errorf("serve http: %w", err)
		}
		a.log.Info("server stopped")
		return nil
	case err := <-errCh:
		if err != nil {
			return fmt.Errorf("serve http: %w", err)
		}
		return nil
	}
}

// Close releases application resources.
func (a *Application) Close() {
	a.closeOnce.Do(func() {
		for _, closer := range a.closers {
			if err := closer.Close(); err != nil {
				a.log.Warn("close resource", slog.String("error", err.Error()))
			}
		}
	})
}

// NewHandler creates the server HTTP handler.
func NewHandler(info buildinfo.Info) http.Handler {
	return NewHandlerWithAuth(info, nil, nil, nil)
}

// NewHandlerWithAuth creates the server HTTP handler with optional auth routes.
func NewHandlerWithAuth(info buildinfo.Info, authService httpapi.AuthService, syncService httpapi.SyncService, verifier httpapi.TokenVerifier) http.Handler {
	info = info.Normalized()
	mux := http.NewServeMux()

	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if !allowMethod(w, r, http.MethodGet) {
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})

	mux.HandleFunc("/version", func(w http.ResponseWriter, r *http.Request) {
		if !allowMethod(w, r, http.MethodGet) {
			return
		}
		writeJSON(w, http.StatusOK, info)
	})

	httpapi.NewAuthHandler(authService).RegisterRoutes(mux)
	httpapi.NewSyncHandler(syncService, verifier).RegisterRoutes(mux)

	return httpapi.RequestIDMiddleware(mux)
}

type runtimeServices struct {
	authService *auth.Service
	syncService *syncsvc.Service
	verifier    httpapi.TokenVerifier
	closer      io.Closer
}

func buildRuntimeServices(ctx context.Context, cfg config.Server) (runtimeServices, error) {
	if strings.TrimSpace(cfg.DatabaseDSN) == "" {
		return runtimeServices{}, nil
	}
	if len(strings.TrimSpace(cfg.AccessTokenSecret)) < 32 {
		return runtimeServices{}, errors.New("access token secret must be at least 32 bytes when database dsn is configured")
	}

	db, err := sql.Open("pgx", cfg.DatabaseDSN)
	if err != nil {
		return runtimeServices{}, fmt.Errorf("open postgres: %w", err)
	}

	setupCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err = db.PingContext(setupCtx); err != nil {
		_ = db.Close()
		return runtimeServices{}, fmt.Errorf("ping postgres: %w", err)
	}
	if err = postgres.MigrateUp(setupCtx, db, migrations.FS); err != nil {
		_ = db.Close()
		return runtimeServices{}, fmt.Errorf("apply migrations: %w", err)
	}

	tokenService, err := tokens.NewService(tokens.Config{
		Issuer:       "gophkeeper",
		AccessSecret: []byte(cfg.AccessTokenSecret),
		AccessTTL:    cfg.AccessTokenTTL,
		RefreshTTL:   cfg.RefreshTokenTTL,
	})
	if err != nil {
		_ = db.Close()
		return runtimeServices{}, err
	}

	authService, err := auth.NewService(auth.Config{
		Users:         postgres.NewUserRepository(db),
		RefreshTokens: postgres.NewRefreshTokenRepository(db),
		Tokens:        tokenService,
		KDFParams:     cryptoutil.DefaultKDFParams(),
	})
	if err != nil {
		_ = db.Close()
		return runtimeServices{}, err
	}

	syncService, err := syncsvc.NewService(
		postgres.NewVaultItemRepository(db),
		postgres.NewSyncStateRepository(db),
		nil,
	)
	if err != nil {
		_ = db.Close()
		return runtimeServices{}, err
	}

	return runtimeServices{
		authService: authService,
		syncService: syncService,
		verifier:    tokenService,
		closer:      db,
	}, nil
}

func allowMethod(w http.ResponseWriter, r *http.Request, method string) bool {
	if r.Method == method {
		return true
	}
	w.Header().Set("Allow", method)
	http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
	return false
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(value); err != nil {
		panic(err)
	}
}

func printUsage(w io.Writer) {
	_, _ = io.WriteString(w, usage)
}
