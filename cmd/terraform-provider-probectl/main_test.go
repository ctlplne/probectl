// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/ctlplne/probectl/internal/version"
)

func TestWriteVersion(t *testing.T) {
	original := version.Version
	t.Cleanup(func() { version.Version = original })
	version.Version = "9.8.7-planted-stamp"

	for _, arg := range []string{"version", "-version", "--version"} {
		var out bytes.Buffer
		if !writeVersion([]string{"terraform-provider-probectl", arg}, &out) {
			t.Fatalf("%s was not handled", arg)
		}
		if got := strings.TrimSpace(out.String()); !strings.Contains(got, version.Version) {
			t.Fatalf("%s output = %q, want shared build stamp %q", arg, got, version.Version)
		}
	}

	var out bytes.Buffer
	if writeVersion([]string{"terraform-provider-probectl"}, &out) ||
		writeVersion([]string{"terraform-provider-probectl", "serve"}, &out) {
		t.Fatal("normal Terraform plugin invocation was intercepted as a version request")
	}
}
