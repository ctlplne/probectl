// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package ebpf

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// TestInstallSeccompProfileWritesTheBundledProfile is the unit half of the
// RTO-12 seccomp-installer change: the agent binary itself installs the
// chart's bundled profile (no busybox), byte for byte, world-readable, into a
// directory it creates, replacing an older copy.
func TestInstallSeccompProfileWritesTheBundledProfile(t *testing.T) {
	src := filepath.Join(repoRootForDeployContract(t), "deploy/helm/probectl-agent/files/seccomp.json")
	want, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(t.TempDir(), "kubelet-seccomp", "probectl", "seccomp.json")
	for i := 0; i < 2; i++ { // second run replaces the first copy
		if err := InstallSeccompProfile(src, dest); err != nil {
			t.Fatalf("run %d: %v", i, err)
		}
	}
	got, err := os.ReadFile(dest)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("installed profile differs from the chart's bundled profile")
	}
	fi, err := os.Stat(dest)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o644 {
		t.Errorf("profile mode = %v, want 0644 (the kubelet must read it)", fi.Mode().Perm())
	}
	leftovers, _ := filepath.Glob(filepath.Join(filepath.Dir(dest), ".probectl-seccomp-*"))
	if len(leftovers) != 0 {
		t.Errorf("temporary files left behind: %v", leftovers)
	}
}

func TestInstallSeccompProfileFailsClosed(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "good.json")
	if err := os.WriteFile(good, []byte(`{"defaultAction":"SCMP_ACT_ERRNO","syscalls":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	notProfile := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(notProfile, []byte(`{"syscalls":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	garbage := filepath.Join(dir, "garbage")
	if err := os.WriteFile(garbage, []byte("#!/bin/sh\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "out", "link.json")
	if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, "elsewhere"), link); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, src, dest string }{
		{"not a seccomp profile", notProfile, filepath.Join(dir, "out", "a.json")},
		{"not JSON", garbage, filepath.Join(dir, "out", "b.json")},
		{"missing source", filepath.Join(dir, "absent.json"), filepath.Join(dir, "out", "c.json")},
		{"relative dest", good, "probectl/seccomp.json"},
		{"unclean dest", good, filepath.Join(dir, "out") + "/../out/d.json"},
		{"symlink dest", good, link},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := InstallSeccompProfile(tc.src, tc.dest); err == nil {
				t.Fatalf("InstallSeccompProfile(%q, %q) succeeded", tc.src, tc.dest)
			}
		})
	}
	if _, err := os.Lstat(filepath.Join(dir, "elsewhere")); err == nil {
		t.Error("the profile was written through a symlink")
	}
}
