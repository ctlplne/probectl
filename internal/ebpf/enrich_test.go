package ebpf

import (
	"os"
	"path/filepath"
	"testing"
)

func TestProcEnricherFromFixtureProcfs(t *testing.T) {
	root := t.TempDir()
	pidDir := filepath.Join(root, "4242")
	if err := os.MkdirAll(pidDir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(pidDir, "comm"), "nginx\n")
	writeFile(t, filepath.Join(pidDir, "cgroup"), "0::/system.slice/docker-"+hex64('a')+".scope\n")

	e := NewProcEnricher(root)
	f := &Flow{Source: Endpoint{Address: "10.0.0.1", PID: 4242}}
	e.Enrich(f)

	if f.Source.Process != "nginx" {
		t.Errorf("process = %q, want nginx", f.Source.Process)
	}
	if f.Source.Container != hex64('a') {
		t.Errorf("container = %q, want the 64-hex id", f.Source.Container)
	}
	if f.Source.Workload == "" {
		t.Error("workload should be resolved from process/container")
	}
}

func TestContainerIDFromCgroup(t *testing.T) {
	id := hex64('b')
	cases := map[string]string{
		"docker-v1":     "11:devices:/docker/" + id,
		"containerd-v2": "0::/kubepods/pod123/cri-containerd-" + id + ".scope",
		"crio":          "0::/machine.slice/crio-" + id + ".scope",
		"none":          "0::/system.slice/sshd.service",
	}
	for name, line := range cases {
		got := containerIDFromCgroup(line)
		if name == "none" {
			if got != "" {
				t.Errorf("%s: got %q, want empty", name, got)
			}
			continue
		}
		if got != id {
			t.Errorf("%s: got %q, want %q", name, got, id)
		}
	}
}

func TestNopEnricherDoesNothing(t *testing.T) {
	f := &Flow{Source: Endpoint{PID: 1}}
	NopEnricher{}.Enrich(f)
	if f.Source.Process != "" || f.Source.Container != "" {
		t.Error("nop enricher must not modify the flow")
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// hex64 returns a 64-char hex string of the given byte (a valid container id).
func hex64(c byte) string {
	out := make([]byte, 64)
	for i := range out {
		out[i] = c
	}
	return string(out)
}
