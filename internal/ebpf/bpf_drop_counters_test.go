// SPDX-License-Identifier: LicenseRef-probectl-TBD

package ebpf

import (
	"os"
	"strings"
	"testing"
)

func TestBPFProgramsCountKernelSideDrops(t *testing.T) {
	l4 := readBPFSource(t, "bpf/l4flow.bpf.c")
	for _, want := range []string{
		"BPF_MAP_TYPE_PERCPU_ARRAY",
		"drop_counters SEC(\".maps\")",
		"count_drop(DROP_RINGBUF_FULL)",
	} {
		if !strings.Contains(l4, want) {
			t.Fatalf("l4flow.bpf.c missing %q: ring-buffer reserve failures must be counted in-kernel", want)
		}
	}
	if strings.Contains(l4, "userspace counts this as a drop") {
		t.Fatal("l4flow.bpf.c still claims userspace can count failed ringbuf reserves")
	}

	ssl := readBPFSource(t, "bpf/sslsniff.bpf.c")
	for _, want := range []string{
		"BPF_MAP_TYPE_PERCPU_ARRAY",
		"drop_counters SEC(\".maps\")",
		"count_drop(DROP_RINGBUF_FULL)",
		"count_drop(DROP_ACTIVE_READS_UPDATE)",
	} {
		if !strings.Contains(ssl, want) {
			t.Fatalf("sslsniff.bpf.c missing %q: TLS reserve/stash failures must be counted in-kernel", want)
		}
	}
	if strings.Contains(ssl, "userspace counts the drop") {
		t.Fatal("sslsniff.bpf.c still claims userspace can count failed ringbuf reserves")
	}
}

func TestL4BPFProgramCapturesIPv6AndTCPVolume(t *testing.T) {
	l4 := readBPFSource(t, "bpf/l4flow.bpf.c")
	for _, want := range []string{
		"AF_INET6",
		"saddr_v6",
		"daddr_v6",
		"bytes_acked",
		"bytes_received",
		"data_segs_out",
		"data_segs_in",
		"BPF_TCP_CLOSE",
	} {
		if !strings.Contains(l4, want) {
			t.Fatalf("l4flow.bpf.c missing %q: IPv6 and byte/packet capture must stay wired", want)
		}
	}
	for _, stale := range []string{
		"IPv4 only today",
		"ctx->family != AF_INET) {",
	} {
		if strings.Contains(l4, stale) {
			t.Fatalf("l4flow.bpf.c still contains stale IPv4-only path %q", stale)
		}
	}
}

func readBPFSource(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
