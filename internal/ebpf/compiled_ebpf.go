//go:build ebpf

package ebpf

// liveCompiled is true when built with -tags ebpf: the cilium/ebpf live source
// is linked in (see source_live_linux.go).
const liveCompiled = true
