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

func readBPFSource(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
