// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/tags"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type ManualTagAssignmentInput struct {
	tags.Scope
	TagID             string
	TargetKind        string
	TargetID          string
	ExporterAgentID   string
	ExporterSourceRef string
	Value             string
}

type TagAssignmentRecord struct {
	ID string `json:"id"`
	tags.Assignment
	ExporterAgentID   string     `json:"exporter_agent_id,omitempty"`
	ExporterSourceRef string     `json:"exporter_source_ref,omitempty"`
	ReviewedAt        *time.Time `json:"reviewed_at,omitempty"`
}

// TagAssignments stores manual annotations and explicitly reviewed imports.
// Separate write paths prevent manual updates from erasing import provenance.
type TagAssignments struct{}

func (TagAssignments) CreateManual(ctx context.Context, sc tenancy.Scope,
	input ManualTagAssignmentInput) (TagAssignmentRecord, error) {
	record, fields, err := manualAssignment(input, sc)
	if err != nil {
		return TagAssignmentRecord{}, err
	}
	id, err := crypto.UUIDv4()
	if err != nil {
		return TagAssignmentRecord{}, err
	}
	record.ID = id
	if err := lockTagAssignmentRevision(ctx, sc); err != nil {
		return TagAssignmentRecord{}, err
	}
	_, err = sc.Q.Exec(ctx, `INSERT INTO tenant_tag_assignments
		(tenant_id,context_id,id,tag_id,target_kind,entity_id,entity_kind,
		 agent_id,test_id,exporter_agent_id,exporter_source_kind,
		 exporter_source_ref,value,source)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,'manual')`,
		input.TenantID, input.ContextID, id, input.TagID, input.TargetKind,
		fields.entityID, fields.entityKind, fields.agentID, fields.testID,
		fields.exporterAgentID, fields.exporterSourceKind, fields.exporterSourceRef,
		input.Value)
	if err != nil {
		return TagAssignmentRecord{}, tagAssignmentError(err)
	}
	return record, nil
}

func (TagAssignments) UpdateManual(ctx context.Context, sc tenancy.Scope, id string,
	input ManualTagAssignmentInput) (TagAssignmentRecord, error) {
	if _, err := uuid.Parse(id); err != nil {
		return TagAssignmentRecord{}, tags.ErrInvalid
	}
	record, fields, err := manualAssignment(input, sc)
	if err != nil {
		return TagAssignmentRecord{}, err
	}
	record.ID = id
	result, err := sc.Q.Exec(ctx, `UPDATE tenant_tag_assignments SET
		tag_id=$4,target_kind=$5,entity_id=$6,entity_kind=$7,
		agent_id=$8,test_id=$9,exporter_agent_id=$10,
		exporter_source_kind=$11,exporter_source_ref=$12,value=$13
		WHERE tenant_id=$1 AND context_id=$2 AND id=$3 AND source='manual'`,
		input.TenantID, input.ContextID, id, input.TagID, input.TargetKind,
		fields.entityID, fields.entityKind, fields.agentID, fields.testID,
		fields.exporterAgentID, fields.exporterSourceKind, fields.exporterSourceRef,
		input.Value)
	if err != nil {
		return TagAssignmentRecord{}, tagAssignmentError(err)
	}
	if result.RowsAffected() == 0 {
		return TagAssignmentRecord{}, pgx.ErrNoRows
	}
	return record, nil
}

func (TagAssignments) DeleteManual(ctx context.Context, sc tenancy.Scope,
	contextID, id string) error {
	result, err := sc.Q.Exec(ctx, `DELETE FROM tenant_tag_assignments
		WHERE tenant_id=$1 AND context_id=$2 AND id=$3 AND source='manual'`,
		sc.Tenant.String(), contextID, id)
	if err != nil {
		return tagAssignmentError(err)
	}
	if result.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	return nil
}

func (TagAssignments) List(ctx context.Context, sc tenancy.Scope, contextID,
	cursor string, limit int) ([]TagAssignmentRecord, string, error) {
	if limit < 1 || limit > 100 {
		return nil, "", tags.ErrInvalid
	}
	if cursor != "" {
		if _, err := uuid.Parse(cursor); err != nil {
			return nil, "", tags.ErrInvalid
		}
	}
	rows, err := sc.Q.Query(ctx, `SELECT id::text,tag_id::text,target_kind,
		COALESCE(entity_id::text,''),COALESCE(agent_id,''),
		COALESCE(test_id::text,''),COALESCE(exporter_agent_id,''),
		COALESCE(exporter_source_ref,''),value,source,COALESCE(source_ref,''),reviewed_at
		FROM tenant_tag_assignments WHERE tenant_id=$1 AND context_id=$2
		AND ($3::uuid IS NULL OR id > $3::uuid) ORDER BY id LIMIT $4`,
		sc.Tenant.String(), contextID, tagOptional(cursor), limit+1)
	if err != nil {
		return nil, "", tagAssignmentError(err)
	}
	defer rows.Close()
	items := make([]TagAssignmentRecord, 0, limit)
	var page tagPageBudget
	for rows.Next() {
		item := TagAssignmentRecord{Assignment: tags.Assignment{Scope: tags.Scope{
			TenantID: sc.Tenant.String(), ContextID: contextID}}}
		var entityID, agentID, testID string
		if err := rows.Scan(&item.ID, &item.TagID, &item.TargetKind,
			&entityID, &agentID, &testID, &item.ExporterAgentID,
			&item.ExporterSourceRef, &item.Value, &item.Source,
			&item.SourceRef, &item.ReviewedAt); err != nil {
			return nil, "", err
		}
		switch item.TargetKind {
		case "device", "interface", "prefix":
			item.TargetID = entityID
		case "agent":
			item.TargetID = agentID
		case "test":
			item.TargetID = testID
		case "exporter":
			item.TargetID, err = tags.ExporterTargetID(item.ExporterAgentID,
				item.ExporterSourceRef)
			if err != nil {
				return nil, "", err
			}
		default:
			return nil, "", tags.ErrInvalid
		}
		if len(items) == limit {
			return items, items[len(items)-1].ID, nil
		}
		admitted, err := page.admit(item)
		if err != nil {
			return nil, "", err
		}
		if !admitted {
			return items, items[len(items)-1].ID, nil
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, "", err
	}
	return items, "", nil
}

type manualTargetFields struct {
	entityID, entityKind, agentID, testID                  any
	exporterAgentID, exporterSourceKind, exporterSourceRef any
}

func manualAssignment(input ManualTagAssignmentInput, sc tenancy.Scope) (
	TagAssignmentRecord, manualTargetFields, error) {
	if input.TenantID != sc.Tenant.String() {
		return TagAssignmentRecord{}, manualTargetFields{}, tags.ErrScopeMismatch
	}
	assignment := tags.Assignment{Scope: input.Scope, TagID: input.TagID,
		TargetKind: input.TargetKind, TargetID: input.TargetID,
		Value: input.Value, Source: "manual"}
	record := TagAssignmentRecord{Assignment: assignment,
		ExporterAgentID:   input.ExporterAgentID,
		ExporterSourceRef: input.ExporterSourceRef}
	var fields manualTargetFields
	switch input.TargetKind {
	case "device", "interface", "prefix":
		if input.ExporterAgentID != "" || input.ExporterSourceRef != "" {
			return TagAssignmentRecord{}, fields, tags.ErrInvalid
		}
		fields.entityID, fields.entityKind = input.TargetID, input.TargetKind
	case "agent":
		if input.ExporterAgentID != "" || input.ExporterSourceRef != "" {
			return TagAssignmentRecord{}, fields, tags.ErrInvalid
		}
		fields.agentID = input.TargetID
	case "test":
		if input.ExporterAgentID != "" || input.ExporterSourceRef != "" {
			return TagAssignmentRecord{}, fields, tags.ErrInvalid
		}
		fields.testID = input.TargetID
	case "exporter":
		if input.TargetID != "" {
			return TagAssignmentRecord{}, fields, tags.ErrInvalid
		}
		id, err := tags.ExporterTargetID(input.ExporterAgentID, input.ExporterSourceRef)
		if err != nil {
			return TagAssignmentRecord{}, fields, err
		}
		record.TargetID = id
		assignment.TargetID = id
		fields.exporterAgentID = input.ExporterAgentID
		fields.exporterSourceKind = "flow_exporter"
		fields.exporterSourceRef = input.ExporterSourceRef
	default:
		return TagAssignmentRecord{}, fields, tags.ErrInvalid
	}
	if err := tags.ValidateAssignment(assignment); err != nil {
		return TagAssignmentRecord{}, fields, err
	}
	return record, fields, nil
}

func lockTagAssignmentRevision(ctx context.Context, sc tenancy.Scope) error {
	tenantID := sc.Tenant.String()
	if _, err := sc.Q.Exec(ctx, `INSERT INTO tenant_tag_revisions(tenant_id,revision)
		VALUES ($1,1) ON CONFLICT (tenant_id) DO NOTHING`, tenantID); err != nil {
		return err
	}
	var revision int64
	if err := sc.Q.QueryRow(ctx, `SELECT revision FROM tenant_tag_revisions
		WHERE tenant_id=$1 FOR UPDATE`, tenantID).Scan(&revision); err != nil {
		return err
	}
	return nil
}

func tagAssignmentError(err error) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch pgErr.Code {
		case "40001":
			return ErrTagImportChanged
		case "23503":
			return ErrTagReference
		case "23505":
			return tags.ErrConflict
		case "23514", "22P02":
			return tags.ErrInvalid
		}
	}
	return err
}
