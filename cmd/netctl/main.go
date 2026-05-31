// Command netctl is the netctl command-line interface — a web-parity client for
// the control-plane /v1 API (test/agent management). See `netctl help`.
//
// Configuration comes from flags or NETCTL_API_URL / NETCTL_API_TOKEN /
// NETCTL_TENANT. The implementation lives in internal/cli (so it is testable).
package main

import (
	"os"

	"github.com/imfeelingtheagi/netctl/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:], os.Getenv, os.Stdout, os.Stderr))
}
