// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License; see ee/LICENSE.

package pricing

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestVersionedWorksheetCalculatesTenHundredThousandScenarios(t *testing.T) {
	model := readFixture(t)
	report, err := Calculate(model)
	if err != nil {
		t.Fatalf("Calculate: %v", err)
	}
	if !report.Offline {
		t.Fatal("report must identify itself as offline")
	}
	if got, want := len(report.ScenarioResults), 9; got != want {
		t.Fatalf("scenario results = %d, want %d", got, want)
	}
	baseline := resultFor(t, report, "10-tenants", "baseline")
	if got := valueFor(t, baseline.Lines, "agents"); got != 50 {
		t.Fatalf("agents = %v, want 50", got)
	}
	if got := valueFor(t, baseline.Lines, "logical_retained"); !approximatelyEqual(got, 0.25) {
		t.Fatalf("logical retained = %v TB, want 0.25", got)
	}
	if got := valueFor(t, baseline.Lines, "hot_retained"); !approximatelyEqual(got, 0.5) {
		t.Fatalf("hot retained = %v TB, want 0.5", got)
	}
	unknown := lineFor(t, baseline.Lines, "measured_operator_labor")
	if unknown.Value != nil || !reflect.DeepEqual(unknown.UnknownInputs, []string{"measured_operator_hours_month"}) {
		t.Fatalf("unknown measured labor = %#v", unknown)
	}
	for _, line := range baseline.Lines {
		if line.Formula == "" || len(line.Inputs) == 0 {
			t.Errorf("line %s lacks formula/input trace", line.Name)
		}
	}

	enterprise := packageFor(t, baseline.Packages, "Enterprise")
	if enterprise.CapStatus != "within_cap" || value(t, enterprise.MonthlyLicenseUSD) != 2000 {
		t.Fatalf("unexpected Enterprise baseline: %#v", enterprise)
	}
	msp := packageFor(t, baseline.Packages, "MSP")
	if got := value(t, msp.MonthlyLicenseUSD); got != 1750 {
		t.Fatalf("MSP license = %v, want 1750", got)
	}
	thousand := resultFor(t, report, "1000-tenants", "baseline")
	if got := packageFor(t, thousand.Packages, "Enterprise").CapStatus; got != "exceeds_cap" {
		t.Fatalf("Enterprise 1000-tenant cap = %q, want exceeds_cap", got)
	}
	if got := packageFor(t, thousand.Packages, "MSP").CapStatus; got != "within_cap" {
		t.Fatalf("MSP 1000-tenant cap = %q, want within_cap", got)
	}
}

func TestCommittedSummaryMatchesCalculator(t *testing.T) {
	report, err := Calculate(readFixture(t))
	if err != nil {
		t.Fatalf("Calculate: %v", err)
	}
	path := filepath.Join("..", "..", "docs", "pricing", "tco-output-2026-08-09.md")
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%s): %v", path, err)
	}
	if got := RenderMarkdown(report); got != string(want) {
		t.Fatalf("committed summary is stale; rerun probectl-tco\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}

func TestSensitivityChangesRetentionReplicationSamplingAndQueryLoad(t *testing.T) {
	report, err := Calculate(readFixture(t))
	if err != nil {
		t.Fatalf("Calculate: %v", err)
	}
	lean := resultFor(t, report, "100-tenants", "lean")
	baseline := resultFor(t, report, "100-tenants", "baseline")
	high := resultFor(t, report, "100-tenants", "high")
	if !(valueFor(t, lean.Lines, "logical_retained") < valueFor(t, baseline.Lines, "logical_retained")) {
		t.Fatal("lean retention/sampling must reduce logical retained TB")
	}
	if !(valueFor(t, high.Lines, "hot_retained") > valueFor(t, baseline.Lines, "hot_retained")) {
		t.Fatal("high retention/replication must increase hot retained TB")
	}
	if !(valueFor(t, high.Lines, "query_vcpu") > valueFor(t, baseline.Lines, "query_vcpu")) {
		t.Fatal("high query load must increase query vCPU")
	}
}

func TestUnknownNeverBecomesZero(t *testing.T) {
	model := readFixture(t)
	model.Prices.OperatorHour.Value = nil
	model.Prices.OperatorHour.Provenance = "unknown"
	model.Prices.OperatorHour.AsOf = ""
	model.Prices.OperatorHour.Source = ""
	report, err := Calculate(model)
	if err != nil {
		t.Fatalf("Calculate: %v", err)
	}
	result := resultFor(t, report, "10-tenants", "baseline")
	operator := lineFor(t, result.Lines, "operator_labor")
	if operator.Value != nil || !contains(operator.UnknownInputs, "operator_hour") {
		t.Fatalf("operator labor hid unknown input: %#v", operator)
	}
	for _, plan := range result.Packages {
		if plan.MonthlyTCOUSD.Value != nil || !contains(plan.MonthlyTCOUSD.UnknownInputs, "self_hosted_tco_before_license") {
			t.Fatalf("plan %s hid unknown TCO: %#v", plan.Name, plan.MonthlyTCOUSD)
		}
	}
}

func TestInputValidationRequiresDatedKnownProvenance(t *testing.T) {
	model := readFixture(t)
	model.Prices.HotStorageTBMonth.AsOf = ""
	if _, err := Calculate(model); err == nil {
		t.Fatal("expected undated known price to fail")
	}
	model = readFixture(t)
	zero := 0.0
	model.Scenarios[0].CompressionRatio.Value = &zero
	report, err := Calculate(model)
	if err != nil {
		t.Fatalf("zero denominator is represented as an unknown result, not a panic: %v", err)
	}
	if lineFor(t, resultFor(t, report, "10-tenants", "baseline").Lines, "logical_retained").Value != nil {
		t.Fatal("non-finite result must be visibly unknown")
	}
}

func readFixture(t *testing.T) Model {
	t.Helper()
	path := filepath.Join("..", "..", "docs", "pricing", "tco-inputs-2026-08-09.json")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%s): %v", path, err)
	}
	var model Model
	if err := json.Unmarshal(b, &model); err != nil {
		t.Fatalf("Unmarshal fixture: %v", err)
	}
	return model
}

func resultFor(t *testing.T, report Report, scenario, sensitivity string) ScenarioResult {
	t.Helper()
	for _, result := range report.ScenarioResults {
		if result.Scenario == scenario && result.Sensitivity == sensitivity {
			return result
		}
	}
	t.Fatalf("missing result %s/%s", scenario, sensitivity)
	return ScenarioResult{}
}

func lineFor(t *testing.T, lines []Line, name string) Line {
	t.Helper()
	for _, line := range lines {
		if line.Name == name {
			return line
		}
	}
	t.Fatalf("missing line %s", name)
	return Line{}
}

func valueFor(t *testing.T, lines []Line, name string) float64 {
	t.Helper()
	return value(t, lineFor(t, lines, name))
}

func value(t *testing.T, line Line) float64 {
	t.Helper()
	if line.Value == nil {
		t.Fatalf("line %s is unknown: %v", line.Name, line.UnknownInputs)
	}
	return *line.Value
}

func packageFor(t *testing.T, packages []PackageResult, name string) PackageResult {
	t.Helper()
	for _, plan := range packages {
		if plan.Name == name {
			return plan
		}
	}
	t.Fatalf("missing package %s", name)
	return PackageResult{}
}

func approximatelyEqual(a, b float64) bool { return a-b < 1e-9 && b-a < 1e-9 }

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
