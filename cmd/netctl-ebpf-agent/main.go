// Command netctl-ebpf-agent is the netctl eBPF host/L7 agent (Linux-only).
//
// S0 scaffold: this entrypoint only reports build information. The CO-RE eBPF
// loader, L3/L4 flow capture, service map, and OTel emission are implemented in
// S20 (the eBPF feasibility spike S19a precedes it). It is observe-only and
// never loads policy-enforcing programs (CLAUDE.md §7 guardrail 8).
package main

import (
	"fmt"

	"github.com/imfeelingtheagi/netctl/internal/version"
)

func main() {
	fmt.Printf("netctl-ebpf-agent %s\n", version.Get())
	fmt.Println("S0 scaffold: the eBPF agent is implemented in S20 (Phase 2).")
}
