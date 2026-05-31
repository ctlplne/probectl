// Command netctl-endpoint is the netctl endpoint / digital-experience (DEM)
// agent.
//
// S0 scaffold: this entrypoint only reports build information. The endpoint
// agent is a Phase 2 deliverable (S37).
package main

import (
	"fmt"

	"github.com/imfeelingtheagi/netctl/internal/version"
)

func main() {
	fmt.Printf("netctl-endpoint %s\n", version.Get())
	fmt.Println("S0 scaffold: the endpoint/DEM agent is implemented in S37 (Phase 2).")
}
