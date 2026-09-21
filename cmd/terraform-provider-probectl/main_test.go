// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

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
