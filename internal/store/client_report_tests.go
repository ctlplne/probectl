// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// ClientReportConfiguredTestsInScope selects every current canonical test
// anchor in this tenant snapshot, independently of incident membership or
// display pages. The existing configured-test reader verifies each enabled
// definition, binding and current identity. Policy callbacks run after closing
// cursors and authorize every canonical member and test; denial returns no
// population prefix. Matching addresses never supply source membership.
func (*EntityRegistry) ClientReportConfiguredTestsInScope(ctx context.Context, sc tenancy.Scope, maxBytes int64, authorize func(context.Context, entity.ContextRecord, IncidentImpactEntity, string) error) ([]IncidentConfiguredTest, error) {
	bound, ok := tenancy.FromContext(ctx)
	if !ok || bound != sc.Tenant || sc.Q == nil || authorize == nil {
		return nil, entity.ErrScopeMismatch
	}
	if err := requireRoutingCaptureReadSnapshot(ctx, sc); err != nil {
		return nil, err
	}
	if maxBytes < 8192 {
		return nil, ErrClientReportBudget
	}
	generation, err := incidentImpactSourceGenerationInScope(ctx, sc)
	if err != nil {
		return nil, err
	}
	rows, err := sc.Q.Query(ctx, `SELECT DISTINCT m.context_id::text,m.anchor_entity_id::text
 FROM entity_source_contexts m JOIN entities node
 ON (node.tenant_id,node.context_id,node.id)=(m.tenant_id,m.context_id,m.anchor_entity_id)
 JOIN tests t ON t.tenant_id=m.tenant_id AND t.enabled
 AND t.id=CASE WHEN m.source_ref ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' THEN m.source_ref::uuid END
 WHERE m.tenant_id=$1 AND node.tenant_id=$1 AND m.source_kind='path_agent'
 AND m.anchor_entity_id IS NOT NULL AND m.assigned_at<=transaction_timestamp()
 AND (m.expires_at IS NULL OR m.expires_at>transaction_timestamp())
 ORDER BY m.context_id::text,m.anchor_entity_id::text LIMIT $2`, bound.String(), maxBytes/2048+1)
	if err != nil {
		return nil, err
	}
	contexts, entities := []string{}, []string{}
	members := map[string]IncidentImpactEntity{}
	remaining := maxBytes / 2
	for rows.Next() {
		if err := ctx.Err(); err != nil {
			rows.Close()
			return nil, err
		}
		if remaining < 1024 {
			rows.Close()
			return nil, ErrClientReportBudget
		}
		var member IncidentImpactEntity
		if err := rows.Scan(&member.ContextID, &member.EntityID); err != nil {
			rows.Close()
			return nil, err
		}
		remaining -= 1024
		members[member.ContextID+":"+member.EntityID] = member
		contexts, entities = append(contexts, member.ContextID), append(entities, member.EntityID)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	for index, contextID := range contexts {
		member := members[contextID+":"+entities[index]]
		record, err := NewEntityRegistry(nil).GetEntityContextInScope(ctx, sc, member.ContextID)
		if err != nil {
			return nil, err
		}
		if err := authorize(ctx, record, member, ""); err != nil {
			return nil, err
		}
	}
	return readIncidentConfiguredTests(ctx, sc, contexts, entities, members, generation, maxBytes/2, authorize)
}

// RecheckClientReportTestsInScope re-resolves only the captured compound keys.
// Newly configured tests cannot add a permission requirement to a frozen pack.
// Current identity may renew; original definition and canonical binding may not
// silently change. This reads configuration/authority, never stored outcomes.
func (*EntityRegistry) RecheckClientReportTestsInScope(ctx context.Context, sc tenancy.Scope, expected []IncidentConfiguredTest, maxBytes int64, authorize func(context.Context, entity.ContextRecord, IncidentImpactEntity, string) error) error {
	bound, ok := tenancy.FromContext(ctx)
	if !ok || bound != sc.Tenant || sc.Q == nil || authorize == nil {
		return entity.ErrScopeMismatch
	}
	if err := requireRoutingCaptureReadSnapshot(ctx, sc); err != nil {
		return err
	}
	if maxBytes < 8192 || int64(len(expected)) > maxBytes/2048 {
		return ErrClientReportBudget
	}
	generation, err := incidentImpactSourceGenerationInScope(ctx, sc)
	if err != nil {
		return err
	}
	contexts, entities := []string{}, []string{}
	members := map[string]IncidentImpactEntity{}
	selected := map[string]IncidentConfiguredTest{}
	for _, item := range expected {
		if item.TenantID != bound.String() {
			return entity.ErrScopeMismatch
		}
		for _, id := range []string{item.ContextID, item.EntityID, item.TestID} {
			if _, err := validRegistryUUID(id); err != nil {
				return err
			}
		}
		if item.AgentID == "" || item.SourceGeneration != generation {
			return errClientReportTestAuthority
		}
		key := clientReportTestKey(item)
		if _, exists := selected[key]; exists {
			return errClientReportTestAuthority
		}
		selected[key] = item
		memberKey := item.ContextID + ":" + item.EntityID
		if _, exists := members[memberKey]; !exists {
			contexts, entities = append(contexts, item.ContextID), append(entities, item.EntityID)
			members[memberKey] = IncidentImpactEntity{ContextID: item.ContextID, EntityID: item.EntityID}
			record, err := NewEntityRegistry(nil).GetEntityContextInScope(ctx, sc, item.ContextID)
			if err != nil {
				return err
			}
			if err := authorize(ctx, record, members[memberKey], ""); err != nil {
				return err
			}
		}
	}
	current, err := readIncidentConfiguredTests(ctx, sc, contexts, entities, members, generation, maxBytes/2, authorize, expected)
	if err != nil {
		return err
	}
	if len(current) != len(selected) {
		return errClientReportTestAuthority
	}
	now := time.Now().UTC()
	for _, item := range current {
		original, ok := selected[clientReportTestKey(item)]
		if !ok || item.MeasurementIdentityUntil == nil || !item.MeasurementIdentityUntil.After(now) {
			return errClientReportTestAuthority
		}
		// Identity expiry is deliberately excluded: renewed current identities are
		// valid. Assignment/definition lineage remains the original capture's.
		a, err := json.Marshal([]any{original.Name, original.Type, original.Target, original.CurrentSince, original.Definition, original.PathBinding})
		if err != nil {
			return err
		}
		b, err := json.Marshal([]any{item.Name, item.Type, item.Target, item.CurrentSince, item.Definition, item.PathBinding})
		if err != nil {
			return err
		}
		if string(a) != string(b) {
			return errClientReportTestAuthority
		}
	}
	return ctx.Err()
}

var errClientReportTestAuthority = errors.New("monthly report configured test authority changed")

func clientReportTestKey(item IncidentConfiguredTest) string {
	return item.ContextID + ":" + item.EntityID + ":" + item.TestID + ":" + item.AgentID
}
