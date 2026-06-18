// SPDX-License-Identifier: LicenseRef-probectl-TBD

package main

import (
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// RESIL-004: the medium production reference may run multiple control-plane
// replicas only while the HA contract says every served read view is coherent.
// Pure RAM views use per-replica fan-in; threat detections read the durable
// tenant-scoped incident_signals store.
func TestMediumReferenceShipsCoherentTopology(t *testing.T) {
	values := readArtifact(t, "deploy/helm/probectl/values-medium.yaml")
	ha := readArtifact(t, "docs/ha.md")

	replicas := topLevelInt(t, values, "replicaCount")

	// Does the HA doc still declare any view that REQUIRES replicaCount 1?
	// (The per-view table marks such views with a bare "1" in the safe-replica
	// column.) We detect it via the documented constraint phrase.
	stillIncoherent := strings.Contains(ha, "Consistent latest-result / threat / TLS views | **1**") ||
		regexp.MustCompile(`want\s+`+"`replicaCount: 1`").MatchString(ha)

	if stillIncoherent {
		t.Fatalf("docs/ha.md still documents views that require replicaCount 1; do not ship the medium HA reference until read-view coherence is restored")
	}

	if replicas < 2 {
		t.Errorf("values-medium.yaml replicaCount must be >= 2 after RESIL-004, got %d", replicas)
	}
	for _, phrase := range []string{
		"per-replica fan-in",
		"incident_signals",
		"replicaCount: 3",
	} {
		if !strings.Contains(ha, phrase) {
			t.Errorf("docs/ha.md must describe %q for the HA read-view contract", phrase)
		}
	}

	// A PodDisruptionBudget minAvailable must not exceed the replica count
	// (an impossible PDB would block all voluntary disruption / upgrades).
	if minAvail, ok := nestedInt(values, "podDisruptionBudget", "minAvailable"); ok && minAvail > replicas {
		t.Errorf("podDisruptionBudget.minAvailable=%d exceeds replicaCount=%d — voluntary disruptions/upgrades would be blocked (OPS-010)", minAvail, replicas)
	}
}

// topLevelInt reads a `key: <int>` at column 0 of a YAML doc.
func topLevelInt(t *testing.T, doc, key string) int {
	t.Helper()
	re := regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(key) + `:\s*(\d+)\s*$`)
	m := re.FindStringSubmatch(doc)
	if m == nil {
		t.Fatalf("could not find top-level %q in values", key)
	}
	n, _ := strconv.Atoi(m[1])
	return n
}

// nestedInt reads `parent:\n  child: <int>` (one level of nesting).
func nestedInt(doc, parent, child string) (int, bool) {
	re := regexp.MustCompile(`(?ms)^` + regexp.QuoteMeta(parent) + `:.*?^\s+` + regexp.QuoteMeta(child) + `:\s*(\d+)`)
	m := re.FindStringSubmatch(doc)
	if m == nil {
		return 0, false
	}
	n, _ := strconv.Atoi(m[1])
	return n, true
}
