// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStageBinaryFileCopiesExecutableReadOnly(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "source")
	destination := filepath.Join(dir, "shared", "probectl-control")
	want := []byte("static executable bytes")
	if err := os.WriteFile(source, want, 0o700); err != nil {
		t.Fatal(err)
	}

	if err := stageBinaryFile(source, destination); err != nil {
		t.Fatalf("stage binary: %v", err)
	}
	got, err := os.ReadFile(destination)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("staged bytes = %q, want %q", got, want)
	}
	info, err := os.Stat(destination)
	if err != nil {
		t.Fatal(err)
	}
	if gotMode := info.Mode().Perm(); gotMode != 0o555 {
		t.Fatalf("staged mode = %#o, want 0555", gotMode)
	}
}

func TestStageBinaryFileReplacesStaleCopy(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "source")
	destination := filepath.Join(dir, "probectl-control")
	if err := os.WriteFile(source, []byte("current"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(destination, []byte("stale"), 0o700); err != nil {
		t.Fatal(err)
	}

	if err := stageBinaryFile(source, destination); err != nil {
		t.Fatalf("replace staged binary: %v", err)
	}
	got, err := os.ReadFile(destination)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "current" {
		t.Fatalf("staged bytes = %q, want current", got)
	}
}

func TestDispatchEarlyCommandRecognizesStageBinary(t *testing.T) {
	oldArgs := os.Args
	t.Cleanup(func() { os.Args = oldArgs })
	os.Args = []string{"probectl-control", "stage-binary"}

	handled, err := dispatchEarlyCommand("stage-binary")
	if !handled {
		t.Fatal("stage-binary was not handled as an early no-database command")
	}
	if err == nil || !strings.Contains(err.Error(), "stage-binary <destination>") {
		t.Fatalf("stage-binary error = %v, want usage error", err)
	}
}
