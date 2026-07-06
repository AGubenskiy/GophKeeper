// Command gk-server runs the GophKeeper HTTP server.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/AGubenskiy/GophKeeper/internal/buildinfo"
	"github.com/AGubenskiy/GophKeeper/internal/serverapp"
)

var (
	version   = "dev"
	buildDate = "unknown"
	commit    = "none"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	info := buildinfo.New(version, buildDate, commit)
	os.Exit(serverapp.Run(ctx, os.Args[1:], os.Stdout, os.Stderr, info))
}
