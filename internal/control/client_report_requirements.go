// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"encoding/json"
	"time"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// Version three requirements contain canonical metadata and required checks;
// they contain no principal, outcome payload, current permission or read grant.
type clientReportSourceRequirements struct {
	Captured     bool                            `json:"captured"`
	Generation   int64                           `json:"generation"`
	From         time.Time                       `json:"from"`
	To           time.Time                       `json:"to"`
	InputsDigest string                          `json:"inputs_digest"`
	Tests        []store.ReportTestRequirement   `json:"tests"`
	Bindings     []store.ReportSourceBinding     `json:"bindings"`
	Access       []clientReportAccessRequirement `json:"access"`
}

func clientReportRequirements(c *clientReportCapture) (*clientReportSourceRequirements, error) {
	tests, err := store.ClientReportTestRequirements(c.Sources)
	if err != nil {
		return nil, err
	}
	return &clientReportSourceRequirements{Captured: true, Generation: c.SourceGeneration, From: c.From, To: c.To, InputsDigest: c.InputsDigest, Tests: tests, Bindings: c.bindings, Access: c.access.requirements}, nil
}

func validateClientReportRequirements(ctx context.Context, tenant string, value *clientReportSourceRequirements, memory int64) error {
	bound, ok := tenancy.FromContext(ctx)
	if !ok || bound.String() != tenant || !reportRequirementUUID(tenant) || value == nil || !value.Captured || value.Generation <= 0 || value.From.IsZero() || !value.To.After(value.From) || value.To.After(time.Now().UTC()) || !canonicalFlowRoutingDigest(value.InputsDigest) || value.Tests == nil || value.Bindings == nil || len(value.Access) == 0 || memory <= 0 {
		return errReportSourceRequirements
	}
	if int64(len(value.Tests)+len(value.Bindings)+len(value.Access)) > memory/2048 {
		return errReportSourceRequirements
	}
	required := map[string]bool{permTestRead: false, permIncidentRead: false, permChangeRead: false, "metrics.read": false, "entities.read": false}
	keys := map[store.ReportSourceKey]bool{}
	for _, binding := range value.Bindings {
		if !reportRequirementUUID(binding.Key.ContextID) || binding.Key.AgentID == "" || binding.Key.Ref == "" || binding.SourceAssignedAt.IsZero() || binding.AgentAssignedAt.IsZero() || !canonicalFlowRoutingDigest(binding.RoutingBindingsDigest) || keys[binding.Key] {
			return errReportSourceRequirements
		}
		if binding.Anchor != nil && !reportRequirementUUID(*binding.Anchor) {
			return errReportSourceRequirements
		}
		keys[binding.Key] = true
	}
	for _, test := range value.Tests {
		if test.TenantID != tenant || test.SourceGeneration != value.Generation || !reportRequirementUUID(test.TestID) || !reportRequirementUUID(test.ContextID) || !reportRequirementUUID(test.EntityID) || !keys[store.ReportSourceKey{ContextID: test.ContextID, AgentID: test.AgentID, Kind: "path_agent", Ref: test.TestID}] {
			return errReportSourceRequirements
		}
	}
	for _, item := range value.Access {
		if !clientReportSourcePermission(item.Permission) || item.Resource[auth.ResourceTenantKey] != tenant {
			return errReportSourceRequirements
		}
		if id := item.Resource["context_id"]; id != "" && !reportRequirementUUID(id) {
			return errReportSourceRequirements
		}
		if len(item.Resource) == 1 {
			if _, ok := required[item.Permission]; ok {
				required[item.Permission] = true
			}
		}
	}
	for _, present := range required {
		if !present {
			return errReportSourceRequirements
		}
	}
	return ctx.Err()
}

func (s *Server) revalidateClientReportRequirementsScope(ctx context.Context, sc tenancy.Scope, actor *auth.Principal, tenant string, value *clientReportSourceRequirements) error {
	budget := flowstore.ExplorerQueryBudget(s.flowStore)
	if err := validateClientReportRequirements(ctx, tenant, value, budget.MemoryBytes/4); err != nil {
		return err
	}
	if actor == nil || actor.TenantID != tenant || sc.Tenant.String() != tenant {
		return errReportSourceRequirements
	}
	if err := s.revalidateClientReportAccessScope(ctx, sc, actor, value.Access); err != nil {
		return err
	}
	current, err := readCurrentUserAuthorityScope(ctx, sc, actor.UserID)
	if err != nil {
		return err
	}
	ctx, principal, err := current.requestContext(ctx, actor)
	if err != nil {
		return err
	}
	if err := store.NewEntityRegistry(s.pool).RecheckClientReportTestRequirementsInScope(ctx, sc, value.Tests, budget.MemoryBytes/8, func(ctx context.Context, record entity.ContextRecord, member store.IncidentImpactEntity, testID string) error {
		resource := entityContextResource(record)
		resource["entity_id"], resource["test_id"] = member.EntityID, testID
		return s.authorizeClientReportTests(ctx, principal, resource)
	}); err != nil {
		return err
	}
	var generation int64
	if err := sc.Q.QueryRow(ctx, `SELECT COALESCE(e.generation,1) FROM (VALUES($1::uuid)) t(id)
 LEFT JOIN flow_snapshot_epochs e ON e.tenant_id=t.id WHERE NOT COALESCE(e.invalidating OR e.observation_erasing,false)`, tenant).Scan(&generation); err != nil {
		return err
	}
	if generation != value.Generation {
		return errReportSourceRequirements
	}
	keys := make([]store.ReportSourceKey, 0, len(value.Bindings))
	for _, item := range value.Bindings {
		keys = append(keys, item.Key)
	}
	bindings, err := store.NewEntityRegistry(s.pool).ReportSourceBindingsInScope(ctx, sc, keys, budget.MemoryBytes/16)
	if err != nil {
		return err
	}
	original := map[store.ReportSourceKey]string{}
	for _, binding := range value.Bindings {
		raw, err := json.Marshal(binding)
		if err != nil {
			return err
		}
		original[binding.Key] = string(raw)
	}
	for _, binding := range bindings {
		raw, err := json.Marshal(binding)
		if err != nil {
			return err
		}
		if original[binding.Key] != string(raw) {
			return errReportSourceRequirements
		}
	}
	return ctx.Err()
}
