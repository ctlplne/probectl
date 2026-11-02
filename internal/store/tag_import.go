// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"context"
	"net/netip"
	"strconv"

	"github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/tags"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type NetBoxTagTarget struct {
	ContextID         string `json:"context_id"`
	TagID             string `json:"tag_id"`
	TagKey            string `json:"tag_key"`
	TargetKind        string `json:"target_kind"`
	TargetID          string `json:"target_id"`
	ExporterAgentID   string `json:"exporter_agent_id"`
	ExporterSourceRef string `json:"exporter_source_ref"`
	TagRevision       string `json:"tag_revision"`
}

// NetBoxExporterTarget resolves an owned canonical exporter and tag before a
// source request. Neither a display label nor a free-form lookup key selects
// the NetBox object. FORCE RLS and compound predicates bind every local row
// (docs/guardrails.md G7-1).
func (TagAssignments) NetBoxExporterTarget(ctx context.Context, sc tenancy.Scope,
	contextID, tagID, agentID, sourceRef string) (NetBoxTagTarget, error) {
	for _, value := range []string{contextID, tagID} {
		id, err := uuid.Parse(value)
		if err != nil || id == uuid.Nil || id.String() != value {
			return NetBoxTagTarget{}, tags.ErrInvalid
		}
	}
	targetID, err := tags.ExporterTargetID(agentID, sourceRef)
	if err != nil || sc.Tenant == "" {
		return NetBoxTagTarget{}, tags.ErrScopeMismatch
	}
	address, err := netip.ParseAddr(sourceRef)
	if err != nil || address.Zone() != "" || address.Unmap().String() != sourceRef {
		return NetBoxTagTarget{}, tags.ErrInvalid
	}
	target := NetBoxTagTarget{ContextID: contextID, TagID: tagID,
		TargetKind: "exporter", TargetID: targetID, ExporterAgentID: agentID}
	var revision int64
	err = sc.Q.QueryRow(ctx, `SELECT d.key,r.revision,s.source_ref
		FROM tenant_tag_definitions d
		JOIN tenant_tag_revisions r ON r.tenant_id=d.tenant_id
		JOIN entity_source_contexts s ON s.tenant_id=d.tenant_id
		JOIN entity_agent_contexts a ON a.tenant_id=s.tenant_id
		 AND a.agent_id=s.agent_id AND a.context_id=s.context_id
		WHERE d.tenant_id=$1 AND r.tenant_id=$1 AND s.tenant_id=$1 AND a.tenant_id=$1
		 AND d.id=$3 AND s.context_id=$2 AND s.agent_id=$4
		 AND s.source_kind='flow_exporter' AND s.source_ref=$5
		 AND s.assigned_at<=now() AND (s.expires_at IS NULL OR s.expires_at>now())
		 AND a.assigned_at<=now() AND (a.expires_at IS NULL OR a.expires_at>now())
		 AND NOT EXISTS (
		  SELECT 1 FROM entity_source_contexts alt_source
		  JOIN entity_agent_contexts alt_agent ON alt_agent.tenant_id=alt_source.tenant_id
		   AND alt_agent.agent_id=alt_source.agent_id AND alt_agent.context_id=alt_source.context_id
		  WHERE alt_source.tenant_id=$1 AND alt_agent.tenant_id=$1
		   AND alt_source.source_kind='flow_exporter' AND alt_source.source_ref=s.source_ref
		   AND (alt_source.agent_id<>s.agent_id OR alt_source.context_id<>s.context_id)
		   AND alt_source.assigned_at<=now() AND (alt_source.expires_at IS NULL OR alt_source.expires_at>now())
		   AND alt_agent.assigned_at<=now() AND (alt_agent.expires_at IS NULL OR alt_agent.expires_at>now()))`,
		sc.Tenant.String(), contextID, tagID, agentID, sourceRef).
		Scan(&target.TagKey, &revision, &target.ExporterSourceRef)
	if err != nil {
		return NetBoxTagTarget{}, tagAssignmentError(err)
	}
	target.TagRevision = strconv.FormatInt(revision, 10)
	return target, nil
}
