// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package bakeoff

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestRepresentativeCatalogKeepsBuyerKnobsSeparateFromFacts(t *testing.T) {
	catalog, profile := readInputs(t)
	wantScenarios := []string{
		"isp-proof", "remote-user", "msp-onboarding-psa", "route-flow-incident",
		"alert-cascade", "upgrade-restore", "cost",
	}
	gotScenarios := make([]string, 0, len(catalog.Scenarios))
	for _, scenario := range catalog.Scenarios {
		gotScenarios = append(gotScenarios, scenario.ID)
	}
	if !reflect.DeepEqual(gotScenarios, wantScenarios) {
		t.Fatalf("scenarios = %v, want %v", gotScenarios, wantScenarios)
	}
	report, err := Evaluate(catalog, profile)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if got := report.Volumes["tenants"].Value; got != 100 {
		t.Fatalf("tenant volume = %v, want 100", got)
	}
	before := catalog.Candidates[0].Results[0]
	profile.Volumes["tenants"] = Volume{Value: 1000, Unit: "count"}
	profile.Weights["isp-proof"] = 1
	if _, err := Evaluate(catalog, profile); err != nil {
		t.Fatalf("Evaluate modified profile: %v", err)
	}
	if !reflect.DeepEqual(catalog.Candidates[0].Results[0], before) {
		t.Fatal("editing buyer profile mutated source facts")
	}
}

func TestUnknownAndUnsupportedAreNeverNumericZero(t *testing.T) {
	catalog, profile := readInputs(t)
	report, err := Evaluate(catalog, profile)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	for _, summary := range report.Summaries {
		if summary.RankingEligible || summary.WeightedPassRate != nil {
			t.Fatalf("incomplete candidate %s was numerically ranked: %#v", summary.Candidate, summary)
		}
		if len(summary.BlockingCells) == 0 {
			t.Fatalf("candidate %s must name its unknown/unsupported cells", summary.Candidate)
		}
	}
}

func TestScoredCellsRequireEvidence(t *testing.T) {
	catalog, profile := readInputs(t)
	catalog.Candidates[0].Results[0].Evidence = nil
	if _, err := Evaluate(catalog, profile); err == nil {
		t.Fatal("expected scored cell without evidence to fail")
	}
	catalog, profile = readInputs(t)
	catalog.Candidates[1].Results[0].Status = StatusUnsupported
	report, err := Evaluate(catalog, profile)
	if err != nil {
		t.Fatalf("explicit unsupported: %v", err)
	}
	if report.Summaries[1].WeightedPassRate != nil {
		t.Fatal("unsupported cell became a zero score")
	}
}

func TestCommittedReportMatchesEvaluation(t *testing.T) {
	catalog, profile := readInputs(t)
	report, err := Evaluate(catalog, profile)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	wantPath := filepath.Join("testdata", "report.golden.md")
	want, err := os.ReadFile(wantPath)
	if err != nil {
		t.Fatalf("ReadFile(%s): %v", wantPath, err)
	}
	if got := RenderMarkdown(report); got != string(want) {
		t.Fatalf("committed report is stale\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}

func readInputs(t *testing.T) (Catalog, Profile) {
	t.Helper()
	// Fixtures live in testdata, not in docs/: they are inputs to this package's
	// round-trip test, not a document probectl ships to anyone.
	base := "testdata"
	var catalog Catalog
	readJSON(t, filepath.Join(base, "catalog.json"), &catalog)
	var profile Profile
	readJSON(t, filepath.Join(base, "msp-design-partner-profile.json"), &profile)
	return catalog, profile
}

func readJSON(t *testing.T, path string, target any) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%s): %v", path, err)
	}
	if err := json.Unmarshal(b, target); err != nil {
		t.Fatalf("Unmarshal(%s): %v", path, err)
	}
}
