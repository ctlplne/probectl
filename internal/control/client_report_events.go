// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"encoding/hex"
	"time"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/change"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/incident"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type clientReportEventCapture struct {
	Incidents       []incident.Incident
	Changes         []change.Event
	IncidentLineage map[string]string
}

// Event capture shares the report's current principal and RLS snapshot. A
// month is independent of interactive incident/change pages. Canonical incident
// members must all pass current context policy; free-form targets never grant
// entity access. Configuration changes require both archive and change reads.
func (s *Server) captureClientReportEventsInScope(ctx context.Context, sc tenancy.Scope, actor *auth.Principal, from, to time.Time, memory int64) (*clientReportEventCapture, error) {
	bound, ok := tenancy.FromContext(ctx)
	if !ok || bound != sc.Tenant || actor == nil || actor.TenantID != bound.String() || sc.Q == nil {
		return nil, entity.ErrScopeMismatch
	}
	resource := map[string]string{auth.ResourceTenantKey: actor.TenantID}
	for _, permission := range []string{permIncidentRead, permChangeRead, "metrics.read"} {
		if err := s.authorize(ctx, actor, permission, auth.RBACGlobal, resource); err != nil {
			return nil, err
		}
	}
	incidents, err := (store.Incidents{}).ClientReportIncidentsInScope(ctx, sc, from, to, memory/8)
	if err != nil {
		return nil, err
	}
	lineage := make(map[string]string, len(incidents))
	for _, item := range incidents {
		digest, err := s.authorizeClientReportIncidentInScope(ctx, sc, actor, item.ID, memory/8)
		if err != nil {
			return nil, err
		}
		lineage[item.ID] = digest
	}
	changes, err := (store.ChangeEvents{}).ClientReportChangesInScope(ctx, sc, from, to, memory/4)
	if err != nil {
		return nil, err
	}
	projected, err := (store.ChangeEvents{}).ClientReportConfigChangesInScope(ctx, sc, from, to, memory/4)
	if err != nil {
		return nil, err
	}
	changes = append(changes, projected...)
	var configRefs []change.Event
	for _, item := range changes {
		resource := map[string]string{auth.ResourceTenantKey: actor.TenantID, "change_id": item.ID, "target": item.Target, "prefix": item.Prefix}
		if err := s.authorize(ctx, actor, permChangeRead, auth.RBACGlobal, resource); err != nil {
			return nil, err
		}
		if item.Config != nil {
			resource["device"] = item.Target
			if err := s.authorize(ctx, actor, "metrics.read", auth.RBACGlobal, resource); err != nil {
				return nil, err
			}
			if binding := item.Config.Binding; binding != nil {
				configRefs = append(configRefs, item)
				record, err := store.NewEntityRegistry(s.pool).GetEntityContextInScope(ctx, sc, binding.ContextID)
				if err != nil {
					return nil, err
				}
				boundResource := entityContextResource(record)
				boundResource["entity_id"], boundResource["agent_id"], boundResource["source_kind"], boundResource["source_ref"] = binding.DeviceEntityID, binding.AgentID, string(entity.DeviceTarget), binding.SourceRef
				for _, permission := range []string{"metrics.read", "entities.read"} {
					if err := s.authorize(ctx, actor, permission, auth.RBACGlobal, boundResource); err != nil {
						return nil, err
					}
				}
			}
		}
	}
	if err := (store.ChangeEvents{}).VerifyConfigChangeReferencesInScope(ctx, sc, configRefs, memory/4); err != nil {
		return nil, err
	}
	sortChangeEvents(changes)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return &clientReportEventCapture{Incidents: incidents, Changes: changes, IncidentLineage: lineage}, nil
}

func (s *Server) authorizeClientReportIncidentInScope(ctx context.Context, sc tenancy.Scope, actor *auth.Principal, id string, memory int64) (string, error) {
	resource := map[string]string{auth.ResourceTenantKey: actor.TenantID, "incident_id": id}
	if err := s.authorize(ctx, actor, permIncidentRead, auth.RBACGlobal, resource); err != nil {
		return "", err
	}
	inputs, err := (store.Incidents{}).ImpactInputs(ctx, sc, id, memory)
	if err != nil {
		return "", err
	}
	for _, member := range inputs.Entities {
		record, err := store.NewEntityRegistry(s.pool).GetEntityContextInScope(ctx, sc, member.ContextID)
		if err != nil {
			return "", err
		}
		if record.TenantID != actor.TenantID {
			return "", entity.ErrScopeMismatch
		}
		resource := entityContextResource(record)
		resource["incident_id"], resource["entity_id"] = id, member.EntityID
		if err := s.authorize(ctx, actor, permIncidentRead, auth.RBACGlobal, resource); err != nil {
			return "", err
		}
	}
	digest, err := hashFlowRoleInputs(ctx, nil, inputs, memory)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(digest), nil
}
