// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License; see ee/LICENSE.
// Production use requires a valid commercial agreement; resale additionally
// requires an MSP entitlement and reseller agreement.

package silo

import (
	"fmt"

	"github.com/ctlplne/probectl/internal/tenancy"
)

// Later nullable-column and CHECK changes need an explicit catch-up after
// CREATE TABLE LIKE. Foreign keys and restrictive format policies never copy.
func reportArtifactStoragePlan(schema string, tables []string) []string {
	owned := map[string]bool{}
	for _, table := range TenantOwned(tables) {
		owned[table] = true
	}
	if !owned["dashboard_report_artifact_chunks"] {
		return nil // the public template has not installed the chunk migration
	}
	parent := quoteIdent(schema) + `."dashboard_report_artifacts"`
	child := quoteIdent(schema) + `."dashboard_report_artifact_chunks"`
	shape := `((body_storage='inline' AND content IS NOT NULL
        AND octet_length(content) BETWEEN 1 AND 2097152 AND source_capture IS NULL
        AND (body_bytes IS NULL OR body_bytes=octet_length(content))
        AND (body_digest IS NULL OR octet_length(body_digest)=32))
      OR (body_storage='chunks' AND content IS NULL
        AND body_bytes IS NOT NULL AND body_bytes BETWEEN 1 AND 140737488355328
        AND body_digest IS NOT NULL AND octet_length(body_digest)=32
        AND source_capture IS NOT NULL AND jsonb_typeof(source_capture)='object'
        AND (source_capture @> '{"version":1}'::jsonb OR source_capture @> '{"version":2}'::jsonb)
        AND source_capture->>'tenant_id' IS NOT NULL
        AND source_capture->>'tenant_id'=tenant_id::text
        AND octet_length(source_capture::text)<=1048576)
      OR (body_storage='document-chunks' AND content IS NULL AND source_capture IS NULL
        AND body_bytes IS NOT NULL AND body_bytes BETWEEN 1 AND 140737488355328
        AND body_digest IS NOT NULL AND octet_length(body_digest)=32))`
	statements := []string{
		fmt.Sprintf(`DO $report_shape$ BEGIN
    IF NOT EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid=%s::regclass
        AND conname='dashboard_report_artifacts_body_representation_v4') THEN
        ALTER TABLE %s ADD CONSTRAINT dashboard_report_artifacts_body_representation_v4 CHECK %s NOT VALID;
    END IF;
END $report_shape$`, quoteLiteral(parent), parent, shape),
		"ALTER TABLE " + parent + " DROP CONSTRAINT IF EXISTS dashboard_report_artifacts_body_representation",
		"ALTER TABLE " + parent + " DROP CONSTRAINT IF EXISTS dashboard_report_artifacts_body_representation_v2",
		"ALTER TABLE " + parent + " DROP CONSTRAINT IF EXISTS dashboard_report_artifacts_body_representation_v3",
		fmt.Sprintf(`DO $report_ordinal$ BEGIN
    IF NOT EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid=%s::regclass
        AND conname='dashboard_report_artifact_chunks_ordinal_nonnegative') THEN
        ALTER TABLE %s ADD CONSTRAINT dashboard_report_artifact_chunks_ordinal_nonnegative CHECK (ordinal >= 0) NOT VALID;
    END IF;
END $report_ordinal$`, quoteLiteral(child), child),
		"ALTER TABLE " + child + " DROP CONSTRAINT IF EXISTS dashboard_report_artifact_chunks_ordinal_check",
		"ALTER TABLE " + parent + " ALTER COLUMN content DROP NOT NULL",
		"DROP POLICY IF EXISTS report_artifact_format ON " + parent,
		"CREATE POLICY report_artifact_format ON " + parent + " AS RESTRICTIVE USING (" + tenancy.ReportArtifactFormatPredicate + ") WITH CHECK (" + tenancy.ReportArtifactFormatPredicate + ")",
		fmt.Sprintf(`DO $report_fk$ BEGIN
    IF NOT EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid=%s::regclass
        AND conname='dashboard_report_artifact_chunks_artifact_fk') THEN
        ALTER TABLE %s ADD CONSTRAINT dashboard_report_artifact_chunks_artifact_fk
          FOREIGN KEY(tenant_id,artifact_id) REFERENCES %s(tenant_id,id) ON DELETE CASCADE;
    END IF;
END $report_fk$`, quoteLiteral(child), child, parent),
	}
	return append(statements, reportArtifactRelationshipPlan(schema, owned)...)
}

// LIKE omits the original report-to-view and report-to-schedule references
// too. New writes must use parents inside this same physical tenant target.
func reportArtifactRelationshipPlan(schema string, owned map[string]bool) []string {
	type relation struct{ child, column, parent, name, deletion string }
	var statements []string
	for _, edge := range []relation{
		{"dashboard_report_schedules", "dashboard_id", "dashboard_views", "report_schedule_dashboard_fk", "CASCADE"},
		{"dashboard_report_artifacts", "dashboard_id", "dashboard_views", "report_artifact_dashboard_fk", "CASCADE"},
		{"dashboard_report_artifacts", "schedule_id", "dashboard_report_schedules", "report_artifact_schedule_fk", "RESTRICT"},
	} {
		if !owned[edge.child] || !owned[edge.parent] {
			continue
		}
		child := quoteIdent(schema) + "." + quoteIdent(edge.child)
		parent := quoteIdent(schema) + "." + quoteIdent(edge.parent)
		statements = append(statements, fmt.Sprintf(`DO $report_relationship$ BEGIN
    IF NOT EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid=%s::regclass AND conname=%s) THEN
      ALTER TABLE %s ADD CONSTRAINT %s FOREIGN KEY(tenant_id,%s)
        REFERENCES %s(tenant_id,id) ON DELETE %s NOT VALID;
    END IF;
END $report_relationship$`, quoteLiteral(child), quoteLiteral(edge.name), child,
			quoteIdent(edge.name), quoteIdent(edge.column), parent, edge.deletion))
	}
	return statements
}
