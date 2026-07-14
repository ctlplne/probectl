// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

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
