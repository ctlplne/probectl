// Command probectl is the probectl command-line interface — a web-parity client for
// the control-plane /v1 API (test/agent management). See `probectl help`.
//
// Configuration comes from flags or PROBECTL_API_URL / PROBECTL_API_TOKEN /
// PROBECTL_TENANT. The implementation lives in internal/cli (so it is testable).
package main

import (
	"os"

	"github.com/imfeelingtheagi/probectl/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:], os.Getenv, os.Stdout, os.Stderr))
}
