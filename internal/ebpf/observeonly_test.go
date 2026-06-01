package ebpf

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestBPFProgramsAreObserveOnly enforces CLAUDE.md §7 guardrail 8: the eBPF
// programs may attach only observation hooks and must call no traffic-altering /
// enforcing helper. It parses the C sources, so it runs in the default build —
// no kernel, no clang, no -tags ebpf required — and fails the build if a future
// edit smuggles in enforcement.
func TestBPFProgramsAreObserveOnly(t *testing.T) {
	files, err := filepath.Glob("bpf/*.bpf.c")
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatal("no bpf/*.bpf.c sources found")
	}

	secRe := regexp.MustCompile(`SEC\("([a-zA-Z0-9_./]+)"\)`)
	allowed := []string{"tracepoint/", "kprobe/", "kretprobe/", "raw_tracepoint/", "fentry/", "fexit/", "license", ".maps"}
	forbidden := []string{
		"bpf_redirect", "bpf_redirect_map", "bpf_clone_redirect", "bpf_redirect_neigh", "bpf_redirect_peer",
		"bpf_override_return", "bpf_send_signal", "bpf_send_signal_thread", "bpf_sk_assign",
		"bpf_skb_store_bytes", "bpf_l3_csum_replace", "bpf_l4_csum_replace", "bpf_msg_redirect", "bpf_msg_redirect_map",
	}

	for _, file := range files {
		src, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		text := string(src)

		for _, m := range secRe.FindAllStringSubmatch(text, -1) {
			sec, ok := m[1], false
			for _, p := range allowed {
				if sec == strings.TrimSuffix(p, "/") || strings.HasPrefix(sec, p) {
					ok = true
					break
				}
			}
			if !ok {
				t.Errorf("%s: SEC(%q) is not an allowed observe-only program type", file, sec)
			}
		}

		for _, h := range forbidden {
			if regexp.MustCompile(`\b` + regexp.QuoteMeta(h) + `\s*\(`).MatchString(text) {
				t.Errorf("%s: calls enforcing helper %q — eBPF must be observe-only (CLAUDE.md §7.8)", file, h)
			}
		}
	}
}
