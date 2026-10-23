// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package ebpf

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// maxSeccompProfileBytes bounds the bundled profile read (it is ~10 KiB).
const maxSeccompProfileBytes = 1 << 20

// InstallSeccompProfile copies the bundled strict seccomp profile at src to
// dest — the node's kubelet seccomp root, mounted into the chart's
// install-seccomp-profile initContainer (EBPF-003). It replaces the busybox
// `cp` the chart used to run (RTO-12): the initContainer now runs the agent
// image itself, which the image-integrity policy verifies, so no unsigned
// image is part of the privileged DaemonSet.
//
// It fails closed: src must parse as a seccomp profile (a JSON object with a
// defaultAction), dest must be an absolute path that is not a symlink, and the
// file is written to a temporary name in dest's directory and renamed into
// place, so the kubelet never resolves a half-written profile.
func InstallSeccompProfile(src, dest string) error {
	if !filepath.IsAbs(src) || !filepath.IsAbs(dest) || filepath.Clean(dest) != dest {
		return fmt.Errorf("install seccomp profile: src %q and dest %q must be clean absolute paths", src, dest)
	}
	body, err := readSeccompProfile(src)
	if err != nil {
		return err
	}
	if fi, err := os.Lstat(dest); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("install seccomp profile: %s is a symlink; refusing to write through it", dest)
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("install seccomp profile: %w", err)
	}
	dir := filepath.Dir(dest)
	if err := os.MkdirAll(dir, 0o755); err != nil { // #nosec G301 -- the kubelet reads the profile tree
		return fmt.Errorf("install seccomp profile: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".probectl-seccomp-*.tmp")
	if err != nil {
		return fmt.Errorf("install seccomp profile: %w", err)
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err := tmp.Write(body); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("install seccomp profile: %w", err)
	}
	if err := tmp.Chmod(0o644); err != nil { // #nosec G302 -- a public profile the kubelet must read
		_ = tmp.Close()
		return fmt.Errorf("install seccomp profile: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("install seccomp profile: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("install seccomp profile: %w", err)
	}
	if err := os.Rename(tmp.Name(), dest); err != nil {
		return fmt.Errorf("install seccomp profile: %w", err)
	}
	return nil
}

func readSeccompProfile(src string) ([]byte, error) {
	f, err := os.Open(src) // #nosec G304 -- the chart's own ConfigMap mount
	if err != nil {
		return nil, fmt.Errorf("install seccomp profile: %w", err)
	}
	defer func() { _ = f.Close() }()
	body, err := io.ReadAll(io.LimitReader(f, maxSeccompProfileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("install seccomp profile: read %s: %w", src, err)
	}
	if len(body) > maxSeccompProfileBytes {
		return nil, fmt.Errorf("install seccomp profile: %s is larger than %d bytes", src, maxSeccompProfileBytes)
	}
	var profile struct {
		DefaultAction string `json:"defaultAction"`
	}
	if err := json.Unmarshal(body, &profile); err != nil || profile.DefaultAction == "" {
		return nil, fmt.Errorf("install seccomp profile: %s is not a seccomp profile (JSON object with defaultAction)", src)
	}
	return body, nil
}
