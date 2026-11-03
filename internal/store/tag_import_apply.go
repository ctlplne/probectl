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

	"github.com/jackc/pgx/v5"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/tags"
	"github.com/ctlplne/probectl/internal/tenancy"
)

var ErrTagImportChanged = errors.New("tags: reviewed import target or revision changed")

// ApplyNetBoxTag requires the fresh source selection to match current facts
// again in the caller's audited tenant write snapshot. It locks the revision,
// preserves manual precedence and upserts only source=netbox annotations.
func (s TagAssignments) ApplyNetBoxTag(ctx context.Context, sc tenancy.Scope,
	expected NetBoxTagTarget, value, sourceRef string, maxBytes int64,
	matches func(TagImportFacts) bool) (TagAssignmentRecord, error) {
	if matches == nil || sc.Tenant == "" {
		return TagAssignmentRecord{}, tags.ErrInvalid
	}
	assignment := tags.Assignment{Scope: tags.Scope{TenantID: sc.Tenant.String(), ContextID: expected.ContextID},
		TagID: expected.TagID, TargetKind: expected.TargetKind, TargetID: expected.TargetID,
		Value: value, Source: "netbox", SourceRef: sourceRef}
	if tags.ValidateAssignment(assignment) != nil {
		return TagAssignmentRecord{}, tags.ErrInvalid
	}
	want, err := strconv.ParseInt(expected.TagRevision, 10, 64)
	if err != nil || want < 1 || strconv.FormatInt(want, 10) != expected.TagRevision {
		return TagAssignmentRecord{}, tags.ErrInvalid
	}
	var revision int64
	if err := sc.Q.QueryRow(ctx, `SELECT revision FROM tenant_tag_revisions WHERE tenant_id=$1 FOR UPDATE`, sc.Tenant.String()).Scan(&revision); err != nil {
		return TagAssignmentRecord{}, tagAssignmentError(err)
	}
	if revision != want {
		return TagAssignmentRecord{}, ErrTagImportChanged
	}
	ref := TagSubjectReference{Kind: expected.TargetKind, ID: expected.TargetID,
		ExporterAgentID: expected.ExporterAgentID, ExporterSourceRef: expected.ExporterSourceRef}
	if ref.Kind == "exporter" {
		ref.ID = ""
	}
	current, facts, err := s.NetBoxSubjectTarget(ctx, sc, expected.ContextID, expected.TagID, ref, maxBytes)
	if err != nil {
		return TagAssignmentRecord{}, err
	}
	if current != expected || !matches(facts) {
		return TagAssignmentRecord{}, ErrTagImportChanged
	}
	input := ManualTagAssignmentInput{Scope: assignment.Scope, TagID: assignment.TagID, TargetKind: assignment.TargetKind,
		TargetID: assignment.TargetID, ExporterAgentID: expected.ExporterAgentID, ExporterSourceRef: expected.ExporterSourceRef, Value: value}
	if input.TargetKind == "exporter" {
		input.TargetID = ""
	}
	_, fields, err := manualAssignment(input, sc)
	if err != nil {
		return TagAssignmentRecord{}, err
	}
	return upsertNetBoxTag(ctx, sc, expected, assignment, fields)
}

func upsertNetBoxTag(ctx context.Context, sc tenancy.Scope, target NetBoxTagTarget, assignment tags.Assignment, fields manualTargetFields) (TagAssignmentRecord, error) {
	var total, existing int
	if err := sc.Q.QueryRow(ctx, `SELECT count(*),count(*) FILTER (WHERE context_id=$2 AND tag_id=$3 AND target_kind=$4 AND source='netbox'
  AND entity_id IS NOT DISTINCT FROM $5::uuid AND agent_id IS NOT DISTINCT FROM $6::text
  AND test_id IS NOT DISTINCT FROM $7::uuid AND exporter_agent_id IS NOT DISTINCT FROM $8::text
  AND exporter_source_ref IS NOT DISTINCT FROM $9::text)
  FROM tenant_tag_assignments WHERE tenant_id=$1`, sc.Tenant.String(), target.ContextID, target.TagID, target.TargetKind,
		fields.entityID, fields.agentID, fields.testID, fields.exporterAgentID, fields.exporterSourceRef).Scan(&total, &existing); err != nil {
		return TagAssignmentRecord{}, err
	}
	if total >= tags.MaxAssignments && existing == 0 {
		return TagAssignmentRecord{}, tags.ErrInvalid
	}
	record := TagAssignmentRecord{Assignment: assignment, ExporterAgentID: target.ExporterAgentID, ExporterSourceRef: target.ExporterSourceRef}
	err := sc.Q.QueryRow(ctx, `UPDATE tenant_tag_assignments SET value=$10,source_ref=$11,reviewed_at=clock_timestamp()
  WHERE tenant_id=$1 AND context_id=$2 AND tag_id=$3 AND target_kind=$4 AND source='netbox'
  AND entity_id IS NOT DISTINCT FROM $5::uuid AND agent_id IS NOT DISTINCT FROM $6::text
  AND test_id IS NOT DISTINCT FROM $7::uuid AND exporter_agent_id IS NOT DISTINCT FROM $8::text
  AND exporter_source_ref IS NOT DISTINCT FROM $9::text RETURNING id::text,reviewed_at`,
		sc.Tenant.String(), target.ContextID, target.TagID, target.TargetKind, fields.entityID, fields.agentID, fields.testID,
		fields.exporterAgentID, fields.exporterSourceRef, assignment.Value, assignment.SourceRef).Scan(&record.ID, &record.ReviewedAt)
	if err == nil {
		return record, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return TagAssignmentRecord{}, tagAssignmentError(err)
	}
	id, err := crypto.UUIDv4()
	if err != nil {
		return TagAssignmentRecord{}, err
	}
	err = sc.Q.QueryRow(ctx, `INSERT INTO tenant_tag_assignments
  (tenant_id,context_id,id,tag_id,target_kind,entity_id,entity_kind,agent_id,test_id,
   exporter_agent_id,exporter_source_kind,exporter_source_ref,value,source,source_ref,reviewed_at)
  VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,'netbox',$14,clock_timestamp())
  RETURNING id::text,reviewed_at`, sc.Tenant.String(), target.ContextID, id, target.TagID, target.TargetKind,
		fields.entityID, fields.entityKind, fields.agentID, fields.testID, fields.exporterAgentID, fields.exporterSourceKind,
		fields.exporterSourceRef, assignment.Value, assignment.SourceRef).Scan(&record.ID, &record.ReviewedAt)
	if err != nil {
		return TagAssignmentRecord{}, tagAssignmentError(err)
	}
	return record, nil
}
