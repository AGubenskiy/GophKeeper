package config

import (
	"errors"
	"flag"
	"testing"
	"time"
)

func TestParseServerDefaults(t *testing.T) {
	cfg, err := ParseServer(nil, nil)
	if err != nil {
		t.Fatalf("ParseServer returned error: %v", err)
	}

	if cfg.Address != DefaultServerAddress {
		t.Fatalf("Address = %q, want %q", cfg.Address, DefaultServerAddress)
	}
	if cfg.AccessTokenSecret != "" {
		t.Fatalf("AccessTokenSecret = %q, want empty", cfg.AccessTokenSecret)
	}
	if cfg.AccessTokenTTL != DefaultAccessTokenTTL {
		t.Fatalf("AccessTokenTTL = %s, want %s", cfg.AccessTokenTTL, DefaultAccessTokenTTL)
	}
	if cfg.DatabaseDSN != "" {
		t.Fatalf("DatabaseDSN = %q, want empty", cfg.DatabaseDSN)
	}
	if cfg.LogLevel != DefaultServerLogLevel {
		t.Fatalf("LogLevel = %q, want %q", cfg.LogLevel, DefaultServerLogLevel)
	}
	if cfg.RefreshTokenTTL != DefaultRefreshTokenTTL {
		t.Fatalf("RefreshTokenTTL = %s, want %s", cfg.RefreshTokenTTL, DefaultRefreshTokenTTL)
	}
	if cfg.ShutdownTimeout != DefaultServerShutdownTimeout {
		t.Fatalf("ShutdownTimeout = %s, want %s", cfg.ShutdownTimeout, DefaultServerShutdownTimeout)
	}
}

func TestParseServerFlags(t *testing.T) {
	cfg, err := ParseServer([]string{
		"--access-token-secret", "12345678901234567890123456789012",
		"--access-token-ttl", "10m",
		"--address", "127.0.0.1:9090",
		"--database-dsn", "postgres://localhost/gophkeeper",
		"--log-level", "debug",
		"--refresh-token-ttl", "24h",
		"--shutdown-timeout", "2s",
	}, nil)
	if err != nil {
		t.Fatalf("ParseServer returned error: %v", err)
	}

	if cfg.Address != "127.0.0.1:9090" {
		t.Fatalf("Address = %q, want custom address", cfg.Address)
	}
	if cfg.AccessTokenSecret != "12345678901234567890123456789012" {
		t.Fatalf("AccessTokenSecret = %q, want custom secret", cfg.AccessTokenSecret)
	}
	if cfg.AccessTokenTTL != 10*time.Minute {
		t.Fatalf("AccessTokenTTL = %s, want 10m", cfg.AccessTokenTTL)
	}
	if cfg.DatabaseDSN != "postgres://localhost/gophkeeper" {
		t.Fatalf("DatabaseDSN = %q, want custom dsn", cfg.DatabaseDSN)
	}
	if cfg.LogLevel != "debug" {
		t.Fatalf("LogLevel = %q, want debug", cfg.LogLevel)
	}
	if cfg.RefreshTokenTTL != 24*time.Hour {
		t.Fatalf("RefreshTokenTTL = %s, want 24h", cfg.RefreshTokenTTL)
	}
	if cfg.ShutdownTimeout != 2*time.Second {
		t.Fatalf("ShutdownTimeout = %s, want 2s", cfg.ShutdownTimeout)
	}
}

func TestParseServerEnvOverridesFlags(t *testing.T) {
	env := map[string]string{
		EnvAccessTokenSecret:     "env-secret-1234567890123456789012",
		EnvAccessTokenTTL:        "11m",
		EnvDatabaseDSN:           "postgres://localhost/env",
		EnvRefreshTokenTTL:       "48h",
		EnvServerAddress:         "localhost:9191",
		EnvServerLogLevel:        "warn",
		EnvServerShutdownTimeout: "3s",
	}

	cfg, err := ParseServer([]string{
		"--access-token-secret", "flag-secret-123456789012345678901",
		"--access-token-ttl", "10m",
		"--address", "127.0.0.1:9090",
		"--database-dsn", "postgres://localhost/flag",
		"--log-level", "debug",
		"--refresh-token-ttl", "24h",
		"--shutdown-timeout", "2s",
	}, mapLookup(env))
	if err != nil {
		t.Fatalf("ParseServer returned error: %v", err)
	}

	if cfg.Address != "localhost:9191" {
		t.Fatalf("Address = %q, want env address", cfg.Address)
	}
	if cfg.AccessTokenSecret != "env-secret-1234567890123456789012" {
		t.Fatalf("AccessTokenSecret = %q, want env secret", cfg.AccessTokenSecret)
	}
	if cfg.AccessTokenTTL != 11*time.Minute {
		t.Fatalf("AccessTokenTTL = %s, want 11m", cfg.AccessTokenTTL)
	}
	if cfg.DatabaseDSN != "postgres://localhost/env" {
		t.Fatalf("DatabaseDSN = %q, want env dsn", cfg.DatabaseDSN)
	}
	if cfg.LogLevel != "warn" {
		t.Fatalf("LogLevel = %q, want env log level", cfg.LogLevel)
	}
	if cfg.RefreshTokenTTL != 48*time.Hour {
		t.Fatalf("RefreshTokenTTL = %s, want 48h", cfg.RefreshTokenTTL)
	}
	if cfg.ShutdownTimeout != 3*time.Second {
		t.Fatalf("ShutdownTimeout = %s, want 3s", cfg.ShutdownTimeout)
	}
}

func TestParseServerHelp(t *testing.T) {
	_, err := ParseServer([]string{"--help"}, nil)

	if !errors.Is(err, flag.ErrHelp) {
		t.Fatalf("ParseServer error = %v, want flag.ErrHelp", err)
	}
}

func TestParseServerRejectsUnexpectedArgument(t *testing.T) {
	_, err := ParseServer([]string{"unexpected"}, nil)

	if err == nil {
		t.Fatal("ParseServer returned nil error, want unexpected argument error")
	}
}

func TestParseServerRejectsInvalidEnvDuration(t *testing.T) {
	_, err := ParseServer(nil, mapLookup(map[string]string{
		EnvServerShutdownTimeout: "soon",
	}))

	if err == nil {
		t.Fatal("ParseServer returned nil error, want invalid duration error")
	}
}

func TestParseServerRejectsInvalidTokenDurations(t *testing.T) {
	if _, err := ParseServer(nil, mapLookup(map[string]string{
		EnvAccessTokenTTL: "soon",
	})); err == nil {
		t.Fatal("ParseServer returned nil error, want invalid access token ttl error")
	}

	if _, err := ParseServer(nil, mapLookup(map[string]string{
		EnvRefreshTokenTTL: "later",
	})); err == nil {
		t.Fatal("ParseServer returned nil error, want invalid refresh token ttl error")
	}
}

func TestServerValidateRejectsEmptyAddress(t *testing.T) {
	cfg := DefaultServer()
	cfg.Address = " "

	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate returned nil, want error")
	}
}

func TestServerValidateRejectsNonPositiveShutdownTimeout(t *testing.T) {
	cfg := DefaultServer()
	cfg.ShutdownTimeout = 0

	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate returned nil, want error")
	}
}

func TestServerValidateRejectsNonPositiveTokenTTL(t *testing.T) {
	cfg := DefaultServer()
	cfg.AccessTokenTTL = 0
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate returned nil for access ttl, want error")
	}

	cfg = DefaultServer()
	cfg.RefreshTokenTTL = 0
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate returned nil for refresh ttl, want error")
	}
}

func mapLookup(values map[string]string) EnvLookup {
	return func(name string) (string, bool) {
		value, ok := values[name]
		return value, ok
	}
}
