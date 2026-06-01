// Separate, throwaway spike module (S19a). Intentionally NOT listed in the
// repo go.work, so it is never built/vetted/linted/tested by production CI.
// Run `go mod tidy` on a machine with network access to populate go.sum.
module github.com/imfeelingtheagi/netctl/spike/ebpf

go 1.26

require github.com/cilium/ebpf v0.16.0
