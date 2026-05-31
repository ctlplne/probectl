// Command netctl-control is the netctl control-plane API server.
//
// S0 scaffold: this entrypoint only reports build information so the binary
// builds and runs across the supported architectures. The stateless HTTP API
// server, NETCTL_-prefixed configuration, slog logging, health/readiness
// probes, the Postgres pool, the migration runner, and the domain-error→HTTP
// middleware are implemented in S1.
package main

import (
	"fmt"

	"github.com/imfeelingtheagi/netctl/internal/version"
)

func main() {
	fmt.Printf("netctl-control %s\n", version.Get())
	fmt.Println("S0 scaffold: the control-plane API server is implemented in S1.")
}
