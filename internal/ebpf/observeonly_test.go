// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

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
	// uprobe/uretprobe are observation hooks too (they read args / return values
	// and the plaintext buffer); they alter nothing.
	allowed := []string{"tracepoint/", "kprobe/", "kretprobe/", "uprobe/", "uretprobe/", "raw_tracepoint/", "fentry/", "fexit/", "license", ".maps"}
	// Re-audited against bpf-helpers(7) (EBPF-006, Sprint 0): beyond the
	// redirect/enforce family, every helper that MUTATES state outside the
	// program — user memory, socket state, packet bytes, or headers — is
	// forbidden. bpf_probe_write_user is the memory-corrupting one the
	// original list missed.
	forbidden := []string{
		// traffic redirection / steering
		"bpf_redirect", "bpf_redirect_map", "bpf_clone_redirect", "bpf_redirect_neigh", "bpf_redirect_peer",
		"bpf_sk_redirect_map", "bpf_sk_redirect_hash", "bpf_msg_redirect", "bpf_msg_redirect_map", "bpf_msg_redirect_hash",
		"bpf_sk_assign",
		// process / kernel interference
		"bpf_override_return", "bpf_send_signal", "bpf_send_signal_thread",
		// user-memory writes (EBPF-006 — the memory-corrupting helper)
		"bpf_probe_write_user",
		// socket-state mutation
		"bpf_setsockopt", "bpf_sock_ops_cb_flags_set", "bpf_store_hdr_opt",
		// packet mutation
		"bpf_skb_store_bytes", "bpf_l3_csum_replace", "bpf_l4_csum_replace",
		"bpf_skb_change_proto", "bpf_skb_change_type", "bpf_skb_change_head", "bpf_skb_change_tail",
		"bpf_skb_adjust_room", "bpf_skb_vlan_push", "bpf_skb_vlan_pop",
		"bpf_xdp_adjust_head", "bpf_xdp_adjust_tail", "bpf_xdp_adjust_meta",
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
