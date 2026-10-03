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

// TestStageBinaryRejectsHelpAndDashArgs is the INV-06 regression: `stage-binary`
// must parse its arguments as flags so a help flag or a '-'-prefixed token is
// never mistaken for a destination and copied over. Before the fix,
// stageBinary([]string{"-h"}) returned nil and left a ~50MB file literally named
// "-h" in the working directory. Each case runs in an isolated working directory
// (t.Chdir) so "a file was created" is an unambiguous assertion.
func TestStageBinaryRejectsHelpAndDashArgs(t *testing.T) {
	tests := []struct {
		name      string
		arg       string
		wantError bool // false => help path returns nil; true => usage error
	}{
		{name: "short help", arg: "-h", wantError: false},
		{name: "long help", arg: "--help", wantError: false},
		{name: "unknown flag as destination", arg: "-x", wantError: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			t.Chdir(dir)

			err := stageBinary([]string{tc.arg})
			if tc.wantError && err == nil {
				t.Fatalf("stageBinary(%q) = nil, want a usage error", tc.arg)
			}
			if !tc.wantError && err != nil {
				t.Fatalf("stageBinary(%q) = %v, want nil (help path)", tc.arg, err)
			}

			// Nothing may be staged for a help flag or a '-'-prefixed token: the
			// pre-fix bug was copying the binary to a file named after the token
			// (filepath.Dir("-h") == "."), so assert the working directory stays
			// empty — this is the assertion that fails before the fix.
			entries, rderr := os.ReadDir(".")
			if rderr != nil {
				t.Fatal(rderr)
			}
			if len(entries) != 0 {
				names := make([]string, 0, len(entries))
				for _, e := range entries {
					names = append(names, e.Name())
				}
				t.Fatalf("stageBinary(%q) staged file(s) %v; want nothing created for a flag argument", tc.arg, names)
			}
		})
	}
}

// TestStageBinaryAcceptsPlainDestination proves the fix does not break the happy
// path: a normal relative destination is accepted and the running executable
// (here the test binary) is staged to it.
func TestStageBinaryAcceptsPlainDestination(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	const dest = "staged-control"
	if err := stageBinary([]string{dest}); err != nil {
		t.Fatalf("stageBinary(%q) = %v, want it to stage the binary", dest, err)
	}
	info, err := os.Stat(dest)
	if err != nil {
		t.Fatalf("expected staged file %q: %v", dest, err)
	}
	if !info.Mode().IsRegular() || info.Size() == 0 {
		t.Fatalf("staged file %q is not a non-empty regular file (mode %v, size %d)", dest, info.Mode(), info.Size())
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
