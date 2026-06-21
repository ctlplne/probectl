// SPDX-License-Identifier: LicenseRef-probectl-TBD

package chaos

import (
	"slices"
	"strings"
	"testing"
)

func TestDependencyChaosMatrixCoversRequiredFaults(t *testing.T) {
	required := map[string][]string{
		"bus-kafka-producer":      {"Kafka", "unreachable"},
		"bus-memory-handler":      {"memory bus", "handler"},
		"result-tsdb-store":       {"TSDB", "DLQ"},
		"flow-device-otlp-stores": {"OTLP", "tenant"},
		"clickhouse-telemetry":    {"ClickHouse", "breaker"},
		"postgres-control-plane":  {"Postgres", "writer"},
		"edge-disk-buffer":        {"disk", "byte cap"},
		"memory-pressure":         {"memory", "cardinality"},
		"control-plane-replica":   {"replica", "group"},
	}

	seen := map[string]DependencyScenario{}
	for _, scenario := range DependencyChaosMatrix() {
		if scenario.ID == "" {
			t.Fatal("scenario with empty ID")
		}
		if _, ok := seen[scenario.ID]; ok {
			t.Fatalf("duplicate scenario ID %q", scenario.ID)
		}
		seen[scenario.ID] = scenario
	}

	for id, needles := range required {
		scenario, ok := seen[id]
		if !ok {
			t.Fatalf("missing required dependency-chaos scenario %q", id)
		}
		haystack := strings.Join([]string{
			scenario.Dependency,
			scenario.Fault,
			scenario.BlastRadius,
			strings.Join(scenario.ExpectedSignals, " "),
			scenario.RetryDLQBehavior,
			scenario.RecoveryAssertion,
		}, " ")
		for _, needle := range needles {
			if !strings.Contains(strings.ToLower(haystack), strings.ToLower(needle)) {
				t.Fatalf("scenario %q does not mention %q in its contract: %+v", id, needle, scenario)
			}
		}
	}
}

func TestDependencyChaosMatrixHasRunnableEvidence(t *testing.T) {
	validPackages := map[string]bool{
		"./cmd/probectl-control":     true,
		"./internal/agent":           true,
		"./internal/bus":             true,
		"./internal/chaos":           true,
		"./internal/control":         true,
		"./internal/pipeline":        true,
		"./internal/store/chclient":  true,
		"./internal/store/chmigrate": true,
		"./internal/store/tsdb":      true,
	}

	for _, scenario := range DependencyChaosMatrix() {
		if scenario.Dependency == "" || scenario.Fault == "" || scenario.BlastRadius == "" {
			t.Fatalf("scenario %q is missing dependency, fault, or blast radius: %+v", scenario.ID, scenario)
		}
		if len(scenario.ExpectedSignals) == 0 {
			t.Fatalf("scenario %q has no expected counters/signals", scenario.ID)
		}
		if scenario.RetryDLQBehavior == "" {
			t.Fatalf("scenario %q has no retry/DLQ behavior", scenario.ID)
		}
		if scenario.RecoveryAssertion == "" {
			t.Fatalf("scenario %q has no recovery assertion", scenario.ID)
		}
		if len(scenario.Evidence) == 0 {
			t.Fatalf("scenario %q has no concrete evidence", scenario.ID)
		}
		for _, evidence := range scenario.Evidence {
			if !validPackages[evidence.Package] {
				t.Fatalf("scenario %q references unmanaged package %q", scenario.ID, evidence.Package)
			}
			if !strings.HasPrefix(evidence.TestPattern, "Test") {
				t.Fatalf("scenario %q evidence %q is not a Go test pattern", scenario.ID, evidence.TestPattern)
			}
		}
	}
}

func TestDependencyChaosMatrixReturnsCopy(t *testing.T) {
	got := DependencyChaosMatrix()
	if len(got) == 0 {
		t.Fatal("empty dependency-chaos matrix")
	}
	got[0].ExpectedSignals[0] = "mutated"
	got[0].Evidence[0].Package = "./mutated"

	again := DependencyChaosMatrix()
	if slices.Contains(again[0].ExpectedSignals, "mutated") {
		t.Fatal("ExpectedSignals slice was not copied")
	}
	if again[0].Evidence[0].Package == "./mutated" {
		t.Fatal("Evidence slice was not copied")
	}
}
