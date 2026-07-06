package logger

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

func TestParseLevel(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  slog.Level
	}{
		{name: "empty", value: "", want: slog.LevelInfo},
		{name: "debug", value: "debug", want: slog.LevelDebug},
		{name: "warning alias", value: "warning", want: slog.LevelWarn},
		{name: "trimmed", value: " ERROR ", want: slog.LevelError},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseLevel(tt.value)
			if err != nil {
				t.Fatalf("ParseLevel returned error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("ParseLevel = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestParseLevelRejectsUnknownValue(t *testing.T) {
	if _, err := ParseLevel("verbose"); err == nil {
		t.Fatal("ParseLevel returned nil error, want unsupported level error")
	}
}

func TestNewWritesJSON(t *testing.T) {
	var out bytes.Buffer

	log, err := New(&out, "info")
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}

	log.Info("started")

	if !strings.Contains(out.String(), `"msg":"started"`) {
		t.Fatalf("log output = %q, want JSON message", out.String())
	}
}
