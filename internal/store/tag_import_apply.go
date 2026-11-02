// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"context"
	"errors"
	"strconv"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/tags"
	"github.com/ctlplne/probectl/internal/tenancy"
)

var ErrTagImportChanged = errors.New("tags: reviewed import target or revision changed")

// ApplyNetBoxExporter accepts only a freshly attested source value. The caller
// compares that fresh source candidate to the reviewed preview first. This
// transaction locks the tenant revision and resolves the owned target again
// before upserting provenance; the caller appends its audit in the same scope.
func (s TagAssignments) ApplyNetBoxExporter(ctx context.Context, sc tenancy.Scope,
	expected NetBoxTagTarget, value, sourceRef string) (TagAssignmentRecord, error) {
	assignment := tags.Assignment{Scope: tags.Scope{TenantID: sc.Tenant.String(),
		ContextID: expected.ContextID}, TagID: expected.TagID,
		TargetKind: expected.TargetKind, TargetID: expected.TargetID,
		Value: value, Source: "netbox", SourceRef: sourceRef}
	if sc.Tenant == "" || expected.TargetKind != "exporter" || tags.ValidateAssignment(assignment) != nil {
		return TagAssignmentRecord{}, tags.ErrInvalid
	}
	want, err := strconv.ParseInt(expected.TagRevision, 10, 64)
	if err != nil || want < 1 || strconv.FormatInt(want, 10) != expected.TagRevision {
		return TagAssignmentRecord{}, tags.ErrInvalid
	}
	var revision int64
	if err := sc.Q.QueryRow(ctx, `SELECT revision FROM tenant_tag_revisions
		WHERE tenant_id=$1 FOR UPDATE`, sc.Tenant.String()).Scan(&revision); err != nil {
		return TagAssignmentRecord{}, tagAssignmentError(err)
	}
	if revision != want {
		return TagAssignmentRecord{}, ErrTagImportChanged
	}
	current, err := s.NetBoxExporterTarget(ctx, sc, expected.ContextID,
		expected.TagID, expected.ExporterAgentID, expected.ExporterSourceRef)
	if err != nil {
		return TagAssignmentRecord{}, err
	}
	if current != expected {
		return TagAssignmentRecord{}, ErrTagImportChanged
	}
	var total, existing int
	if err := sc.Q.QueryRow(ctx, `SELECT count(*),count(*) FILTER (
		WHERE context_id=$2 AND tag_id=$3 AND exporter_agent_id=$4
		 AND exporter_source_ref=$5 AND source='netbox')
		FROM tenant_tag_assignments WHERE tenant_id=$1`, sc.Tenant.String(),
		expected.ContextID, expected.TagID, expected.ExporterAgentID,
		expected.ExporterSourceRef).Scan(&total, &existing); err != nil {
		return TagAssignmentRecord{}, err
	}
	if total >= tags.MaxAssignments && existing == 0 {
		return TagAssignmentRecord{}, tags.ErrInvalid
	}
	id, err := crypto.UUIDv4()
	if err != nil {
		return TagAssignmentRecord{}, err
	}
	record := TagAssignmentRecord{Assignment: assignment,
		ExporterAgentID: expected.ExporterAgentID, ExporterSourceRef: expected.ExporterSourceRef}
	err = sc.Q.QueryRow(ctx, `INSERT INTO tenant_tag_assignments
		(tenant_id,context_id,id,tag_id,target_kind,exporter_agent_id,
		 exporter_source_kind,exporter_source_ref,value,source,source_ref,reviewed_at)
		VALUES ($1,$2,$3,$4,'exporter',$5,'flow_exporter',$6,$7,'netbox',$8,clock_timestamp())
		ON CONFLICT (tenant_id,context_id,tag_id,exporter_agent_id,exporter_source_ref,source)
		 WHERE exporter_agent_id IS NOT NULL
		DO UPDATE SET value=EXCLUDED.value,source_ref=EXCLUDED.source_ref,reviewed_at=EXCLUDED.reviewed_at
		RETURNING id::text,reviewed_at`, sc.Tenant.String(), expected.ContextID,
		id, expected.TagID, expected.ExporterAgentID, expected.ExporterSourceRef,
		value, sourceRef).Scan(&record.ID, &record.ReviewedAt)
	if err != nil {
		return TagAssignmentRecord{}, tagAssignmentError(err)
	}
	return record, nil
}
