package config

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"
)

const (
	// EnvAccessTokenSecret overrides the JWT signing secret.
	EnvAccessTokenSecret = "GOPHKEEPER_ACCESS_TOKEN_SECRET"
	// EnvAccessTokenTTL overrides the JWT access token lifetime.
	EnvAccessTokenTTL = "GOPHKEEPER_ACCESS_TOKEN_TTL"
	// EnvDatabaseDSN overrides the PostgreSQL connection string.
	EnvDatabaseDSN = "GOPHKEEPER_DATABASE_DSN"
	// EnvRefreshTokenTTL overrides the refresh token lifetime.
	EnvRefreshTokenTTL = "GOPHKEEPER_REFRESH_TOKEN_TTL"
	// EnvServerAddress overrides the server listen address.
	EnvServerAddress = "GOPHKEEPER_SERVER_ADDRESS"
	// EnvServerLogLevel overrides the server log level.
	EnvServerLogLevel = "GOPHKEEPER_SERVER_LOG_LEVEL"
	// EnvServerShutdownTimeout overrides the graceful shutdown timeout.
	EnvServerShutdownTimeout = "GOPHKEEPER_SERVER_SHUTDOWN_TIMEOUT"
	// EnvTLSCertFile overrides the TLS certificate file path.
	EnvTLSCertFile = "GOPHKEEPER_TLS_CERT_FILE"
	// EnvTLSKeyFile overrides the TLS private key file path.
	EnvTLSKeyFile = "GOPHKEEPER_TLS_KEY_FILE"
)

const (
	// DefaultAccessTokenTTL is the default JWT access token lifetime.
	DefaultAccessTokenTTL = 15 * time.Minute
	// DefaultRefreshTokenTTL is the default refresh token lifetime.
	DefaultRefreshTokenTTL = 30 * 24 * time.Hour
	// DefaultServerAddress is the default TCP address for the HTTP server.
	DefaultServerAddress = "localhost:8080"
	// DefaultServerLogLevel is the default structured log level.
	DefaultServerLogLevel = "info"
	// DefaultServerShutdownTimeout is the default graceful shutdown deadline.
	DefaultServerShutdownTimeout = 5 * time.Second
)

// EnvLookup reads an environment variable by name.
type EnvLookup func(string) (string, bool)

// Server contains HTTP server runtime settings.
type Server struct {
	AccessTokenSecret string
	AccessTokenTTL    time.Duration
	DatabaseDSN       string
	RefreshTokenTTL   time.Duration
	Address           string
	LogLevel          string
	ShutdownTimeout   time.Duration
	TLSCertFile       string
	TLSKeyFile        string
}

// DefaultServer returns default server settings.
func DefaultServer() Server {
	return Server{
		AccessTokenTTL:  DefaultAccessTokenTTL,
		Address:         DefaultServerAddress,
		LogLevel:        DefaultServerLogLevel,
		RefreshTokenTTL: DefaultRefreshTokenTTL,
		ShutdownTimeout: DefaultServerShutdownTimeout,
	}
}

// ParseServer parses server flags and environment overrides.
func ParseServer(args []string, lookup EnvLookup) (Server, error) {
	if lookup == nil {
		lookup = emptyEnv
	}

	defaults := DefaultServer()
	fs := flag.NewFlagSet("gk-server", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	accessTokenSecret := fs.String("access-token-secret", defaults.AccessTokenSecret, "JWT access token signing secret")
	accessTokenTTL := fs.Duration("access-token-ttl", defaults.AccessTokenTTL, "JWT access token lifetime")
	address := fs.String("address", defaults.Address, "HTTP listen address")
	databaseDSN := fs.String("database-dsn", defaults.DatabaseDSN, "PostgreSQL connection string")
	logLevel := fs.String("log-level", defaults.LogLevel, "log level: debug, info, warn, or error")
	refreshTokenTTL := fs.Duration("refresh-token-ttl", defaults.RefreshTokenTTL, "refresh token lifetime")
	shutdownTimeout := fs.Duration("shutdown-timeout", defaults.ShutdownTimeout, "graceful shutdown timeout")
	tlsCertFile := fs.String("tls-cert-file", defaults.TLSCertFile, "TLS certificate file")
	tlsKeyFile := fs.String("tls-key-file", defaults.TLSKeyFile, "TLS private key file")

	if err := fs.Parse(args); err != nil {
		return Server{}, err
	}
	if fs.NArg() > 0 {
		return Server{}, fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}

	cfg := Server{
		AccessTokenSecret: *accessTokenSecret,
		AccessTokenTTL:    *accessTokenTTL,
		DatabaseDSN:       *databaseDSN,
		RefreshTokenTTL:   *refreshTokenTTL,
		Address:           *address,
		LogLevel:          *logLevel,
		ShutdownTimeout:   *shutdownTimeout,
		TLSCertFile:       *tlsCertFile,
		TLSKeyFile:        *tlsKeyFile,
	}

	if value, ok := lookupNonEmpty(lookup, EnvAccessTokenSecret); ok {
		cfg.AccessTokenSecret = value
	}
	if value, ok := lookupNonEmpty(lookup, EnvAccessTokenTTL); ok {
		duration, err := time.ParseDuration(value)
		if err != nil {
			return Server{}, fmt.Errorf("invalid %s value %q: %w", EnvAccessTokenTTL, value, err)
		}
		cfg.AccessTokenTTL = duration
	}
	if value, ok := lookupNonEmpty(lookup, EnvDatabaseDSN); ok {
		cfg.DatabaseDSN = value
	}
	if value, ok := lookupNonEmpty(lookup, EnvRefreshTokenTTL); ok {
		duration, err := time.ParseDuration(value)
		if err != nil {
			return Server{}, fmt.Errorf("invalid %s value %q: %w", EnvRefreshTokenTTL, value, err)
		}
		cfg.RefreshTokenTTL = duration
	}
	if value, ok := lookupNonEmpty(lookup, EnvServerAddress); ok {
		cfg.Address = value
	}
	if value, ok := lookupNonEmpty(lookup, EnvServerLogLevel); ok {
		cfg.LogLevel = value
	}
	if value, ok := lookupNonEmpty(lookup, EnvServerShutdownTimeout); ok {
		duration, err := time.ParseDuration(value)
		if err != nil {
			return Server{}, fmt.Errorf("invalid %s value %q: %w", EnvServerShutdownTimeout, value, err)
		}
		cfg.ShutdownTimeout = duration
	}
	if value, ok := lookupNonEmpty(lookup, EnvTLSCertFile); ok {
		cfg.TLSCertFile = value
	}
	if value, ok := lookupNonEmpty(lookup, EnvTLSKeyFile); ok {
		cfg.TLSKeyFile = value
	}
	cfg.TLSCertFile = strings.TrimSpace(cfg.TLSCertFile)
	cfg.TLSKeyFile = strings.TrimSpace(cfg.TLSKeyFile)

	if err := cfg.Validate(); err != nil {
		return Server{}, err
	}
	return cfg, nil
}

// Validate checks server settings for obvious configuration errors.
func (c Server) Validate() error {
	if c.AccessTokenTTL <= 0 {
		return errors.New("access token ttl must be positive")
	}
	if strings.TrimSpace(c.Address) == "" {
		return errors.New("server address is required")
	}
	if c.RefreshTokenTTL <= 0 {
		return errors.New("refresh token ttl must be positive")
	}
	if c.ShutdownTimeout <= 0 {
		return errors.New("shutdown timeout must be positive")
	}
	if (strings.TrimSpace(c.TLSCertFile) == "") != (strings.TrimSpace(c.TLSKeyFile) == "") {
		return errors.New("tls cert file and tls key file must be provided together")
	}
	return nil
}

func emptyEnv(string) (string, bool) {
	return "", false
}

func lookupNonEmpty(lookup EnvLookup, name string) (string, bool) {
	value, ok := lookup(name)
	if !ok {
		return "", false
	}

	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return "", false
	}
	return trimmed, true
}
