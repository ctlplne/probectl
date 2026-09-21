// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build linux

package ebpf

import (
	"os"
	"path/filepath"
	"testing"
)

// DPR-125, the second half. The first fix taught DISCOVERY to skip a library
// with no execute bit, because cilium/ebpf's loader refuses one. Once the
// in-repo tracefs path could attach to exactly such a library, that filter
// became the thing standing in the way: the shipped DaemonSet still logged
// "libssl found but not attachable ... carries no execute bit" and ran with
// l7:false, on a node whose libssl the agent could now probe.
//
// The execute bit decides which attach path is used. It does not decide whether
// a library is worth discovering.
func TestHostLibraryAttachableAcceptsAPackagedLibrary(t *testing.T) {
	dir := t.TempDir()
	packaged := filepath.Join(dir, "libssl.so.3") // what Debian and Ubuntu ship
	if err := os.WriteFile(packaged, []byte("\x7fELF"), 0o644); err != nil {
		t.Fatal(err)
	}
	executable := filepath.Join(dir, "libssl-exec.so.3") // what RHEL ships
	if err := os.WriteFile(executable, []byte("\x7fELF"), 0o755); err != nil {
		t.Fatal(err)
	}

	if !hostLibraryAttachable(packaged) {
		t.Error("a 0644 library must be attachable: the kernel wants a regular file, and the tracefs path needs nothing more")
	}
	if !hostLibraryAttachable(executable) {
		t.Error("a 0755 library must remain attachable")
	}
	if hostLibraryAttachable(dir) {
		t.Error("a directory is not a library")
	}
	if hostLibraryAttachable(filepath.Join(dir, "absent.so")) {
		t.Error("a path that does not exist is not attachable")
	}
	// A device node or a symlink to nowhere is not a regular file either, and
	// handing one to the kernel is a worse error than declining it here.
	if err := os.Symlink(filepath.Join(dir, "absent.so"), filepath.Join(dir, "dangling.so")); err == nil {
		if hostLibraryAttachable(filepath.Join(dir, "dangling.so")) {
			t.Error("a dangling symlink is not attachable")
		}
	}
}

func TestHostLibraryExistsIgnoresDirectories(t *testing.T) {
	dir := t.TempDir()
	lib := filepath.Join(dir, "libssl.so.3")
	if err := os.WriteFile(lib, []byte("\x7fELF"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !hostLibraryExists(lib) {
		t.Error("a present library must be reported as present whatever its mode")
	}
	if hostLibraryExists(dir) {
		t.Error("a directory is not a library")
	}
}
