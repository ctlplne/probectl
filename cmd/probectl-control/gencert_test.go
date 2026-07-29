// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGenCertIfMissingKeepsCompleteBundle(t *testing.T) {
	dir := t.TempDir()
	if err := genCert([]string{"--if-missing", dir}); err != nil {
		t.Fatalf("first gen-cert: %v", err)
	}

	before := make(map[string][]byte)
	for _, name := range []string{"tls.crt", "tls.key", "ca.crt"} {
		body, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("read first %s: %v", name, err)
		}
		before[name] = body
	}

	if err := genCert([]string{"--if-missing", dir}); err != nil {
		t.Fatalf("second gen-cert: %v", err)
	}
	for name, want := range before {
		got, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("read second %s: %v", name, err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("%s changed even though the complete bundle already existed", name)
		}
	}
}

func TestGenCertIfMissingRejectsIncompleteBundle(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "tls.crt")
	original := []byte("operator certificate")
	if err := os.WriteFile(certPath, original, 0o600); err != nil {
		t.Fatal(err)
	}

	err := genCert([]string{"--if-missing", dir})
	if err == nil || !strings.Contains(err.Error(), "incomplete certificate bundle") {
		t.Fatalf("gen-cert error = %v, want incomplete-bundle refusal", err)
	}
	got, readErr := os.ReadFile(certPath)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if !bytes.Equal(got, original) {
		t.Fatal("gen-cert changed the existing certificate while rejecting a partial bundle")
	}
	for _, name := range []string{"tls.key", "ca.crt"} {
		if _, statErr := os.Stat(filepath.Join(dir, name)); !os.IsNotExist(statErr) {
			t.Fatalf("%s was created while rejecting a partial bundle; stat error = %v", name, statErr)
		}
	}
}
