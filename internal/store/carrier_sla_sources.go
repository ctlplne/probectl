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
	"time"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/tenancy"
)

var ErrCarrierSLASourceUnavailable = errors.New("complete current recorded carrier SLA sources are unavailable")

// CarrierSLAConfiguredTestsInScope resolves only the selected financial
// revision's explicit agent/test pairs. Expected entries supply selectors, not
// canonical contexts or a telemetry grant. The live tenant-composite reference
// and unchanged assignment epoch supply those identities. No whole-tenant scan
// or address match can add a probe to a circuit.
func (*EntityRegistry) CarrierSLAConfiguredTestsInScope(ctx context.Context, sc tenancy.Scope, agreement, version string, expected []IncidentConfiguredTest, memory int64,
	authorize func(context.Context, entity.ContextRecord, IncidentImpactEntity, string) error) ([]IncidentConfiguredTest, error) {
	bound, ok := tenancy.FromContext(ctx)
	if !ok || bound != sc.Tenant || sc.Q == nil || authorize == nil {
		return nil, entity.ErrScopeMismatch
	}
	if err := requireRoutingCaptureReadSnapshot(ctx, sc); err != nil {
		return nil, err
	}
	if _, err := validRegistryUUID(agreement); err != nil {
		return nil, err
	}
	revision, err := strconv.ParseInt(version, 10, 64)
	if err != nil || revision <= 0 || strconv.FormatInt(revision, 10) != version || len(expected) == 0 {
		return nil, ErrCarrierSLASourceUnavailable
	}
	if memory < 8192 || int64(len(expected)) > memory/4096 {
		return nil, ErrClientReportBudget
	}
	agents, tests := []string{}, []string{}
	seen := map[[2]string]bool{}
	remaining := memory / 2
	for _, item := range expected {
		if item.TenantID != bound.String() {
			return nil, entity.ErrScopeMismatch
		}
		if _, err := validRegistryUUID(item.TestID); err != nil {
			return nil, err
		}
		key := [2]string{item.AgentID, item.TestID}
		if item.AgentID == "" || seen[key] {
			return nil, ErrCarrierSLASourceUnavailable
		}
		cost := int64(1024 + len(item.AgentID) + len(item.TestID))
		if cost > remaining {
			return nil, ErrClientReportBudget
		}
		remaining -= cost
		seen[key] = true
		agents, tests = append(agents, item.AgentID), append(tests, item.TestID)
	}
	generation, err := incidentImpactSourceGenerationInScope(ctx, sc)
	if err != nil {
		return nil, err
	}
	rows, err := sc.Q.Query(ctx, `SELECT r.context_id::text,r.device_id::text,r.agent_id,r.test_id::text
 FROM flow_capacity_agreement_sla_refs r
 JOIN unnest($4::text[],$5::uuid[]) selected(agent_id,test_id)
 ON selected.agent_id=r.agent_id AND selected.test_id=r.test_id
 JOIN entity_source_contexts m ON m.tenant_id=$1 AND m.tenant_id=r.tenant_id
 AND m.agent_id=r.agent_id AND m.source_kind=r.source_kind AND m.source_ref=r.source_ref
 JOIN entity_test_contexts c ON c.tenant_id=$1 AND c.tenant_id=r.tenant_id
 AND c.test_id=r.test_id AND c.context_id=r.context_id
 WHERE r.tenant_id=$1 AND r.agreement_id=$2 AND r.version=$3
 AND m.context_id=r.context_id AND m.anchor_entity_id=r.device_id
 AND m.assigned_at=r.source_assigned_at AND m.assigned_at<=transaction_timestamp()
 AND (m.expires_at IS NULL OR m.expires_at>transaction_timestamp())
 ORDER BY r.context_id,r.device_id,r.test_id,r.agent_id`, bound.String(), agreement, revision, agents, tests)
	if err != nil {
		return nil, err
	}
	contexts, entities := []string{}, []string{}
	members := map[string]IncidentImpactEntity{}
	selected := []IncidentConfiguredTest{}
	for rows.Next() {
		item := IncidentConfiguredTest{TenantID: bound.String(), SourceGeneration: generation}
		if err := rows.Scan(&item.ContextID, &item.EntityID, &item.AgentID, &item.TestID); err != nil {
			rows.Close()
			return nil, err
		}
		selected = append(selected, item)
		key := item.ContextID + ":" + item.EntityID
		if _, found := members[key]; !found {
			members[key] = IncidentImpactEntity{ContextID: item.ContextID, EntityID: item.EntityID}
			contexts, entities = append(contexts, item.ContextID), append(entities, item.EntityID)
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	if len(selected) != len(expected) {
		return nil, ErrCarrierSLASourceUnavailable
	}
	out, err := readIncidentConfiguredTests(ctx, sc, contexts, entities, members, generation, memory/2, authorize, selected)
	if err != nil {
		return nil, err
	}
	if len(out) != len(expected) {
		return nil, ErrCarrierSLASourceUnavailable
	}
	now := time.Now().UTC()
	for _, item := range out {
		if item.MeasurementIdentityUntil == nil || !item.MeasurementIdentityUntil.After(now) {
			return nil, ErrCarrierSLASourceUnavailable
		}
	}
	return out, ctx.Err()
}
