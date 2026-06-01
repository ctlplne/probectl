package ebpf

import (
	"runtime"
	"testing"
)

func TestProbeReportsModeAndReason(t *testing.T) {
	c := Probe()
	if c.OS != runtime.GOOS {
		t.Errorf("OS = %q, want %q", c.OS, runtime.GOOS)
	}
	if c.Mode != ModeLive && c.Mode != ModeUnavailable {
		t.Fatalf("mode = %q, want live|unavailable", c.Mode)
	}
	// The default build is not compiled with -tags ebpf, so the live source is
	// not linked in and the mode must be a decided, explained "unavailable".
	if !liveCompiled {
		if c.Mode != ModeUnavailable {
			t.Errorf("mode = %q, want unavailable when not built with -tags ebpf", c.Mode)
		}
		if c.Reason == "" {
			t.Error("unavailable mode must carry a reason")
		}
	}
	_ = c.String()
}
