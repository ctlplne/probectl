//go:build !linux || !ebpf

package ebpf

import "errors"

// newLiveL7Source is unavailable without the eBPF/uprobe layer (the default
// build, macOS/Windows, or Linux without -tags ebpf). Set an l7_fixture_path
// (PROBECTL_EBPF_L7_FIXTURE_PATH) for the no-kernel path, or rebuild with
// -tags ebpf. The real implementation lives in source_live_l7_linux.go.
func newLiveL7Source(*Config) (L7Source, error) {
	return nil, errors.New("ebpf: live L7 capture not compiled in (build -tags ebpf on Linux with clang, or set l7_fixture_path)")
}
