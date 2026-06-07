//go:build linux

package ebpf

import (
	"fmt"
	"os"
)

// lockdownMode reads the active kernel lockdown mode, or "" when securityfs is
// not mounted / the file is absent (lockdown not built in).
func lockdownMode() string {
	data, err := os.ReadFile("/sys/kernel/security/lockdown")
	if err != nil {
		return ""
	}
	return parseLockdown(string(data))
}

// explainBPFLoadError wraps a bpf() load failure with a clear, structured
// degradation message when the cause is kernel lockdown confidentiality mode
// (U-075) — instead of surfacing a bare EPERM/"operation not permitted" that
// looks like a missing capability.
func explainBPFLoadError(err error) error {
	if err == nil {
		return nil
	}
	if lockdownBlocksBPF(lockdownMode()) {
		return fmt.Errorf("ebpf: kernel lockdown is in CONFIDENTIALITY mode, which blocks bpf() even with CAP_BPF — the eBPF agent cannot load programs here; boot without lockdown=confidentiality or use integrity mode (U-075): %w", err)
	}
	return err
}
