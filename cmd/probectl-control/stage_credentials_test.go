// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// projectedSecretDir mimics a Kubernetes Secret volume: the real bytes live
// under ..data/ (group-readable under fsGroup) and the visible names are
// symlinks to them — exactly the shape the strict credential reader refuses.
func projectedSecretDir(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	data := filepath.Join(dir, "..2026_09_17_03_30_00.123")
	if err := os.MkdirAll(data, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Base(data), filepath.Join(dir, "..data")); err != nil {
		t.Fatal(err)
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(data, name), []byte(body), 0o640); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Join("..data", name), filepath.Join(dir, name)); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// DPR-030: a projected Secret volume is rejected by the strict basic-auth
// reader; the staged copy is accepted.
func TestStageCredentialsProducesReaderAcceptableFiles(t *testing.T) {
	src := projectedSecretDir(t, map[string]string{
		"prom-basic-auth.json": `{"username":"probectl","password":"pw-1"}`,
		"ch-basic-auth.json":   `{"username":"probectl","password":"pw-2"}`,
	})
	dst := filepath.Join(t.TempDir(), "credentials")
	if _, err := datastoreBasicAuthFactory(true, filepath.Join(src, "prom-basic-auth.json")); err == nil {
		t.Fatal("the projected (symlinked, 0640) credential must be refused by the strict reader — otherwise this staging step would be pointless")
	}
	if err := stageCredentials([]string{src, dst}); err != nil {
		t.Fatalf("stage-credentials: %v", err)
	}
	for _, name := range []string{"prom-basic-auth.json", "ch-basic-auth.json"} {
		p := filepath.Join(dst, name)
		info, err := os.Lstat(p)
		if err != nil {
			t.Fatalf("%s not staged: %v", name, err)
		}
		if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
			t.Fatalf("%s: mode %v, want a regular 0600 file", name, info.Mode())
		}
		if _, err := datastoreBasicAuthFactory(true, p); err != nil {
			t.Fatalf("staged %s must satisfy the strict reader: %v", name, err)
		}
	}
	if _, err := os.Lstat(filepath.Join(dst, "..data")); !os.IsNotExist(err) {
		t.Fatal("projected bookkeeping entries must not be staged")
	}
	dirInfo, _ := os.Stat(dst)
	if dirInfo.Mode().Perm() != 0o700 {
		t.Fatalf("staging directory mode %v, want 0700", dirInfo.Mode().Perm())
	}
	// Re-running (a pod restart) replaces the files in place.
	if err := stageCredentials([]string{src, dst}); err != nil {
		t.Fatalf("second stage-credentials: %v", err)
	}
	// A pre-existing destination (a volume mount point the process cannot
	// chmod, as in the Helm init container) is used as-is; the files still
	// come out 0600.
	mount := t.TempDir()
	if err := os.Chmod(mount, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := stageCredentials([]string{src, mount}); err != nil {
		t.Fatalf("stage into an existing mount point: %v", err)
	}
	if info, err := os.Lstat(filepath.Join(mount, "ch-basic-auth.json")); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("staged file in mount point: %v %v", info, err)
	}
}

func TestStageCredentialsRefusesEmptyAndOversized(t *testing.T) {
	if err := stageCredentials([]string{t.TempDir(), filepath.Join(t.TempDir(), "out")}); err == nil || !strings.Contains(err.Error(), "no credential files") {
		t.Fatalf("an empty source must be refused, got %v", err)
	}
	big := projectedSecretDir(t, map[string]string{"huge.json": strings.Repeat("x", maxStagedCredentialBytes+1)})
	if err := stageCredentials([]string{big, filepath.Join(t.TempDir(), "out")}); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("an oversized credential must be refused, got %v", err)
	}
	if err := stageCredentials([]string{"only-one"}); err == nil || !strings.Contains(err.Error(), "usage") {
		t.Fatalf("bad arguments must print usage, got %v", err)
	}
}
