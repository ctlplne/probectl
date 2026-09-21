// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package version

import (
	"strings"
	"testing"
)

// TestGetPopulatesRuntimeFields is the trivial unit test that proves the test
// harness and CI are wired correctly (S0). It also guards the contract that
// Get() always fills the runtime-derived fields.
func TestGetPopulatesRuntimeFields(t *testing.T) {
	info := Get()
	if info.GoVersion == "" {
		t.Error("Get().GoVersion should be populated from the runtime")
	}
	if info.OS == "" {
		t.Error("Get().OS should be populated from the runtime")
	}
	if info.Arch == "" {
		t.Error("Get().Arch should be populated from the runtime")
	}
}

func TestGetUsesSharedBuildStamp(t *testing.T) {
	original := Version
	t.Cleanup(func() { Version = original })

	Version = "9.8.7-planted-stamp"
	if got := Get().Version; got != Version {
		t.Fatalf("Get().Version = %q, want linker-stamped shared version %q", got, Version)
	}
}

func TestInfoStringContainsVersion(t *testing.T) {
	info := Info{
		Version: "v1.2.3",
		Commit:  "abc1234",
		Date:    "2026-01-01T00:00:00Z",
	}
	got := info.String()
	if !strings.Contains(got, "v1.2.3") {
		t.Errorf("Info.String() = %q, want it to contain the version %q", got, info.Version)
	}
}

// DPR-148: the commit is baked into every binary, reported on /metrics, and
// asserted in the SIGNED auditor bundle, which tells its reader to fetch the
// SBOM for that build. A build from a modified tree, or one with no VCS
// information, identifies no published artifact — and a document that quotes the
// SHA anyway sends an auditor to compare against the wrong thing.
func TestProvenanceIsOnlyTrustworthyForAnUnmodifiedRevision(t *testing.T) {
	for _, tc := range []struct {
		commit      string
		trustworthy bool
		modified    bool
	}{
		{"7d8338d", true, false},
		{"7d8338d9ffeb0d15ddc9918ffe2626e7dea16b08", true, false},
		{"7d8338d-dirty", false, true},
		{"unknown", false, false},
		{"", false, false},
		{"   ", false, false},
	} {
		got := Info{Commit: tc.commit}
		if got.ProvenanceTrustworthy() != tc.trustworthy {
			t.Errorf("commit %q: trustworthy = %v, want %v", tc.commit, got.ProvenanceTrustworthy(), tc.trustworthy)
		}
		if got.Modified() != tc.modified {
			t.Errorf("commit %q: modified = %v, want %v", tc.commit, got.Modified(), tc.modified)
		}
	}
}
