//go:build !linux || !ebpf

package ebpf

import "errors"

// newLiveSource is unavailable on builds without the eBPF loader: the default
// build, macOS/Windows, or Linux built without -tags ebpf. Set a fixture_path
// (PROBECTL_EBPF_FIXTURE_PATH) for the no-kernel path, or rebuild with -tags ebpf
// on a Linux host with clang + libbpf headers. See docs/ebpf-agent.md. The real
// implementation lives in source_live_linux.go (//go:build linux && ebpf).
func newLiveSource(*Config) (Source, error) {
	return nil, errors.New("ebpf: live source not compiled in (build -tags ebpf on Linux with clang, or set fixture_path)")
}
