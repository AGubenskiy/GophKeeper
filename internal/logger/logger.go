package logger

import (
	"fmt"
	"io"
	"log/slog"
	"strings"
)

// New creates a JSON slog logger for the provided level.
func New(w io.Writer, level string) (*slog.Logger, error) {
	if w == nil {
		w = io.Discard
	}

	parsedLevel, err := ParseLevel(level)
	if err != nil {
		return nil, err
	}

	handler := slog.NewJSONHandler(w, &slog.HandlerOptions{Level: parsedLevel})
	return slog.New(handler), nil
}

// ParseLevel converts a textual log level into a slog level.
func ParseLevel(level string) (slog.Level, error) {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "", "info":
		return slog.LevelInfo, nil
	case "debug":
		return slog.LevelDebug, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return 0, fmt.Errorf("unsupported log level %q", level)
	}
}
