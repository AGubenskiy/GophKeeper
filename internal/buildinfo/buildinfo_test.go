package buildinfo

import (
	"bytes"
	"testing"
)

func TestNewUsesDefaultsForEmptyValues(t *testing.T) {
	info := New(" ", "", "\t")

	if info.Version != "dev" {
		t.Fatalf("Version = %q, want %q", info.Version, "dev")
	}
	if info.Date != "unknown" {
		t.Fatalf("Date = %q, want %q", info.Date, "unknown")
	}
	if info.Commit != "none" {
		t.Fatalf("Commit = %q, want %q", info.Commit, "none")
	}
}

func TestInfoPrint(t *testing.T) {
	var out bytes.Buffer
	info := New("1.2.3", "2026-07-02", "abc123")

	if err := info.Print(&out); err != nil {
		t.Fatalf("Print returned error: %v", err)
	}

	const want = "Build version: 1.2.3\nBuild date: 2026-07-02\nBuild commit: abc123\n"
	if got := out.String(); got != want {
		t.Fatalf("Print output = %q, want %q", got, want)
	}
}
