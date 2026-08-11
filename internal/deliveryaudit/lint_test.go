// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package deliveryaudit

import (
	"slices"
	"testing"
	"time"
)

func TestLintAcceptsCompleteLiveReceipt(t *testing.T) {
	t.Parallel()
	receipt, err := newSelfTestReceipt(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if diagnostics := Lint(receipt); len(diagnostics) != 0 {
		t.Fatalf("Lint() diagnostics = %v, want none", diagnostics)
	}
}

func TestLintRejectsTestOnlyAndUnreachableClaims(t *testing.T) {
	t.Parallel()

	boolPtr := func(value bool) *bool { return &value }
	tests := []struct {
		name   string
		mutate func(*Receipt)
		codes  []string
	}{
		{name: "fixture", mutate: func(r *Receipt) { r.EvidenceSources.Fixture = boolPtr(true) }, codes: []string{"fixture-only"}},
		{name: "mock", mutate: func(r *Receipt) { r.EvidenceSources.Mock = boolPtr(true) }, codes: []string{"fixture-only"}},
		{name: "testdata", mutate: func(r *Receipt) { r.EvidenceSources.TestData = boolPtr(true) }, codes: []string{"fixture-only"}},
		{name: "dev auth", mutate: func(r *Receipt) { r.Build.DevAuth = boolPtr(true) }, codes: []string{"devauth-build"}},
		{name: "placeholder", mutate: func(r *Receipt) { r.Build.PlaceholderUI = boolPtr(true) }, codes: []string{"placeholder-ui"}},
		{name: "dirty", mutate: func(r *Receipt) { r.Source.Dirty = boolPtr(true) }, codes: []string{"dirty-source"}},
		{name: "short sha", mutate: func(r *Receipt) { r.Source.GitSHA = "abc123" }, codes: []string{"exact-sha-required", "release-sha-mismatch"}},
		{name: "build mismatch", mutate: func(r *Receipt) { r.Build.CLICommit = "0000000000000000000000000000000000000000" }, codes: []string{"release-sha-mismatch"}},
		{name: "CLI absent", mutate: func(r *Receipt) { r.CLI.Commands = nil }, codes: []string{"cli-unobserved", "cli-unreachable"}},
		{name: "UI absent", mutate: func(r *Receipt) { r.UI.Routes = nil }, codes: []string{"ui-unobserved", "ui-unreachable"}},
		{name: "browser absent", mutate: func(r *Receipt) { r.BrowserNetwork.Requests = nil }, codes: []string{"browser-network-unobserved"}},
		{name: "stores absent", mutate: func(r *Receipt) { r.Stores = StoreEvidence{} }, codes: []string{"store-probe-failed"}},
		{name: "TLS bypass", mutate: func(r *Receipt) { r.TLS.IgnoreHTTPSErrors = boolPtr(true) }, codes: []string{"tls-trust-unverified"}},
		{name: "long-lived CA", mutate: func(r *Receipt) { r.TLS.CANotBefore = r.TLS.CANotAfter.Add(-24 * time.Hour) }, codes: []string{"tls-trust-unverified"}},
		{name: "same auditor", mutate: func(r *Receipt) { r.Auditor.Agent = r.Auditor.ImplementationOwner }, codes: []string{"independent-auditor-required"}},
		{name: "not human", mutate: func(r *Receipt) { r.HumanPath.Reproduced = boolPtr(false) }, codes: []string{"human-path-not-reproduced"}},
		{name: "binary unreachable", mutate: func(r *Receipt) { r.Reachability.DefaultBuildReachable = boolPtr(false) }, codes: []string{"binary-unreachable"}},
		{name: "default off unactivated", mutate: func(r *Receipt) {
			r.Activation.EnabledByDefault = boolPtr(false)
		}, codes: []string{"default-off-unactivated"}},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			receipt, err := newSelfTestReceipt(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			test.mutate(&receipt)
			got := diagnosticCodes(Lint(receipt))
			for _, code := range test.codes {
				if !slices.Contains(got, code) {
					t.Fatalf("Lint() codes = %v, want %q", got, code)
				}
			}
		})
	}
}

func TestDefaultOffActivationMustBeObservedNotSelfAsserted(t *testing.T) {
	t.Parallel()
	receipt, err := newSelfTestReceipt(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	no := false
	receipt.Activation.EnabledByDefault = &no
	receipt.Activation.EnableCLICommand = "probectl config feature enable incidents"
	receipt.Activation.EnableUIRoute = "/admin/features/incidents"
	if got := diagnosticCodes(Lint(receipt)); !slices.Contains(got, "default-off-unactivated") {
		t.Fatalf("self-asserted activation codes = %v, want default-off-unactivated", got)
	}

	receipt.CLI.Commands = append(receipt.CLI.Commands, receipt.Activation.EnableCLICommand)
	receipt.UI.Routes = append(receipt.UI.Routes, receipt.Activation.EnableUIRoute)
	if got := Lint(receipt); len(got) != 0 {
		t.Fatalf("observed activation diagnostics = %v, want none", got)
	}
}

func diagnosticCodes(diagnostics []Diagnostic) []string {
	out := make([]string, 0, len(diagnostics))
	for _, diagnostic := range diagnostics {
		out = append(out, diagnostic.Code)
	}
	return out
}
