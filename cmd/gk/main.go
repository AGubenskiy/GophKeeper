// Command gk runs the GophKeeper CLI client.
package main

import (
	"os"

	"github.com/AGubenskiy/GophKeeper/internal/buildinfo"
	"github.com/AGubenskiy/GophKeeper/internal/clientapp"
)

var (
	version   = "dev"
	buildDate = "unknown"
	commit    = "none"
)

func main() {
	info := buildinfo.New(version, buildDate, commit)
	os.Exit(clientapp.Run(os.Args[1:], os.Stdout, os.Stderr, info))
}
