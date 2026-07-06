package buildinfo

import (
	"fmt"
	"io"
	"strings"
)

const (
	defaultVersion = "dev"
	defaultDate    = "unknown"
	defaultCommit  = "none"
)

// Info describes build metadata injected into a binary at compile time.
type Info struct {
	Version string `json:"version"`
	Date    string `json:"date"`
	Commit  string `json:"commit"`
}

// New returns normalized build metadata.
func New(version, date, commit string) Info {
	return Info{
		Version: fallback(version, defaultVersion),
		Date:    fallback(date, defaultDate),
		Commit:  fallback(commit, defaultCommit),
	}
}

// Normalized returns a copy with empty fields replaced by stable defaults.
func (i Info) Normalized() Info {
	return New(i.Version, i.Date, i.Commit)
}

// Print writes build metadata in a stable human-readable format.
func (i Info) Print(w io.Writer) error {
	i = i.Normalized()
	_, err := fmt.Fprintf(
		w,
		"Build version: %s\nBuild date: %s\nBuild commit: %s\n",
		i.Version,
		i.Date,
		i.Commit,
	)
	return err
}

func fallback(value, defaultValue string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return defaultValue
	}
	return trimmed
}
