// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestBrowserAgentImageShipsReadableWorkerFiles (DPR-062): the rendered-browser
// image inherited the build host's file modes, so a 0600 checkout produced a
// worker the DaemonSet's uid could not open and every rendered transaction
// failed with EACCES. The Dockerfile must pin the modes of what it copies and
// prove the worker is readable; the chart must run as the image's own user.
func TestBrowserAgentImageShipsReadableWorkerFiles(t *testing.T) {
	root := repoRoot(t)
	df, err := os.ReadFile(filepath.Join(root, "deploy/docker/Dockerfile.browser-agent"))
	if err != nil {
		t.Fatal(err)
	}
	copies := regexp.MustCompile(`(?m)^COPY .*browser-worker/`).FindAllString(string(df), -1)
	if len(copies) < 2 {
		t.Fatalf("expected the worker COPY lines, got %v", copies)
	}
	for _, line := range copies {
		if !strings.Contains(line, "--chmod=0644") {
			t.Errorf("worker COPY without an explicit readable mode: %q", line)
		}
	}
	if !strings.Contains(string(df), "test -r /worker/worker.mjs") {
		t.Error("the image build does not prove the worker is readable")
	}
	ds, err := os.ReadFile(filepath.Join(root, "deploy/helm/probectl/templates/browser-agent.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"runAsUser: 1001", "runAsGroup: 1001", "fsGroup: 1001"} {
		if !strings.Contains(string(ds), want) {
			t.Errorf("browser DaemonSet must run as the image's pwuser (uid 1001): missing %q", want)
		}
	}
}
