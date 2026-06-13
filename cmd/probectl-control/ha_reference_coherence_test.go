// SPDX-License-Identifier: LicenseRef-probectl-TBD

package main

import (
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// OPS-010 / ARCH-003: the default HA reference (values-medium.yaml) must NOT
// ship a topology that is known to be read-incoherent. A few read views
// (/v1/results/latest, threat detections, TLS posture) are still served from
// per-replica process memory, so multiple control-plane replicas can return
// different answers for the same query. Until those views adopt per-replica
// fan-in (or a shared store), the reference must default to replicaCount: 1
// (coherent) — anything higher would ship the known-incoherent topology.
//
// This gate is self-updating: once the doc no longer declares any in-RAM view
// as needing replicaCount 1, a higher default is allowed.
func TestMediumReferenceShipsCoherentTopology(t *testing.T) {
	values := readArtifact(t, "deploy/helm/probectl/values-medium.yaml")
	ha := readArtifact(t, "docs/ha.md")

	replicas := topLevelInt(t, values, "replicaCount")

	// Does the HA doc still declare any view that REQUIRES replicaCount 1?
	// (The per-view table marks such views with a bare "1" in the safe-replica
	// column.) We detect it via the documented constraint phrase.
	stillIncoherent := strings.Contains(ha, "Consistent latest-result / threat / TLS views | **1**") ||
		regexp.MustCompile(`want\s+`+"`replicaCount: 1`").MatchString(ha)

	if stillIncoherent && replicas != 1 {
		t.Errorf("values-medium.yaml defaults replicaCount=%d while docs/ha.md still documents in-RAM views that require replicaCount 1 — the reference ships a known-incoherent topology (OPS-010). Default to 1 or land the view coherence first.", replicas)
	}

	if replicas < 1 {
		t.Errorf("values-medium.yaml replicaCount must be >= 1, got %d", replicas)
	}

	// A PodDisruptionBudget minAvailable must not exceed the replica count
	// (an impossible PDB would block all voluntary disruption / upgrades).
	if min, ok := nestedInt(values, "podDisruptionBudget", "minAvailable"); ok && min > replicas {
		t.Errorf("podDisruptionBudget.minAvailable=%d exceeds replicaCount=%d — voluntary disruptions/upgrades would be blocked (OPS-010)", min, replicas)
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
