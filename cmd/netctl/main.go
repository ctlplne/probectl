// Command netctl is the netctl command-line interface (web-parity CLI/TUI).
//
// S0 scaffold: this entrypoint only reports build information. The CLI skeleton
// (configuration, auth token, and the test/agent subcommands) is implemented in
// S9.
package main

import (
	"fmt"

	"github.com/imfeelingtheagi/netctl/internal/version"
)

func main() {
	fmt.Printf("netctl %s\n", version.Get())
	fmt.Println("S0 scaffold: the CLI command surface is implemented in S9.")
}
