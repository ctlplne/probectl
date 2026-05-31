// Command netctl-agent is the netctl canary/enterprise agent — a single,
// statically linked, multi-arch binary with compiled-in canary plugins.
//
// S0 scaffold: this entrypoint only reports build information. The agent
// runtime, YAML/env configuration, tenant-bound registration over mTLS, the
// canary plugin host, and the disk-backed store-and-forward buffer are
// implemented in S5.
package main

import (
	"fmt"

	"github.com/imfeelingtheagi/netctl/internal/version"
)

func main() {
	fmt.Printf("netctl-agent %s\n", version.Get())
	fmt.Println("S0 scaffold: the agent runtime and plugin host are implemented in S5.")
}
