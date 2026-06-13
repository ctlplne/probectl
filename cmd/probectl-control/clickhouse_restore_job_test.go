// SPDX-License-Identifier: LicenseRef-probectl-TBD

package main

import (
	"strings"
	"testing"
)

// OPS-007: Kubernetes had a chart-managed Postgres restore Job but no
// ClickHouse one — CH restore on K8s was a manual, compose-hardwired script.
// The restore Job template must now also render a ClickHouse restore Job, gated
// on restore.clickhouse.enabled, that invokes the REAL server-side restore path
// (clickhouse-client RESTORE DATABASE ... FROM File(...)) mirroring the CH
// backup CronJob — not a stub.
func TestClickHouseRestoreJobInvokesRealRestorePath(t *testing.T) {
	tmpl := readArtifact(t, "deploy/helm/probectl/templates/restore-job.yaml")

	// A second Job, gated on restore.clickhouse.enabled.
	if !strings.Contains(tmpl, "if .Values.restore.clickhouse.enabled") {
		t.Error("restore-job template must render a CH restore Job gated on restore.clickhouse.enabled (OPS-007)")
	}
	// It must run the real server-side RESTORE (mirrors the CronJob's BACKUP),
	// reading the artifact from the backups PVC.
	if !strings.Contains(tmpl, "RESTORE DATABASE") || !strings.Contains(tmpl, "FROM File(") {
		t.Error("CH restore Job must invoke `RESTORE DATABASE ... FROM File(...)` — the real restore path (OPS-007)")
	}
	if !strings.Contains(tmpl, "clickhouse-client") {
		t.Error("CH restore Job must use clickhouse-client (OPS-007)")
	}
	// Destructive-by-contract: drop the DB first, fail loud (no silent retry).
	if !strings.Contains(tmpl, "DROP DATABASE IF EXISTS") {
		t.Error("CH restore Job must drop the database before RESTORE (OPS-007)")
	}
	if !strings.Contains(tmpl, "ch-restore") {
		t.Error("CH restore Job container should be named ch-restore (OPS-007)")
	}

	// Values + schema must declare restore.clickhouse so the gate is reachable.
	values := readArtifact(t, "deploy/helm/probectl/values.yaml")
	if !strings.Contains(values, "clickhouse:") {
		t.Error("values.yaml restore block must declare a clickhouse sub-block (OPS-007)")
	}
	schema := readArtifact(t, "deploy/helm/probectl/values.schema.json")
	// The schema enforces additionalProperties:false on restore, so the new key
	// must be declared or `helm template` would reject it.
	if !strings.Contains(schema, "\"clickhouse\"") {
		t.Error("values.schema.json must declare restore.clickhouse (additionalProperties:false) (OPS-007)")
	}
}
