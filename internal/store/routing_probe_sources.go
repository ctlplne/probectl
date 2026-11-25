// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"context"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type RoutingProbeTest struct {
	TestID  string `json:"test_id"`
	AgentID string `json:"agent_id"`
}

// RoutingProbeTestsInScope requires both explicitly selected agents and
// tests to be current in the same tenant snapshot as the owned router.
// It reads only the two compound keys and never returns a partial pair.
func (s *EntityRegistry) RoutingProbeTestsInScope(ctx context.Context, sc tenancy.Scope, scope entity.Scope, router string,
	requested [2]RoutingProbeTest, maxBytes int64, authorize func(context.Context, entity.ContextRecord, IncidentImpactEntity, string) error) ([2]IncidentConfiguredTest, error) {
	var out [2]IncidentConfiguredTest
	bound, ok := tenancy.FromContext(ctx)
	if canonical, err := scope.Normalize(); err != nil || canonical != scope || !ok || bound != sc.Tenant ||
		scope.TenantID != bound.String() || sc.Q == nil || authorize == nil {
		return out, entity.ErrScopeMismatch
	}
	if err := requireRoutingCaptureReadSnapshot(ctx, sc); err != nil {
		return out, err
	}
	if canonical, err := validRegistryUUID(router); err != nil || canonical != router {
		return out, entity.ErrInvalidScope
	}
	if requested[0].AgentID == requested[1].AgentID || requested[0].TestID == requested[1].TestID {
		return out, entity.ErrInvalidClaim
	}
	var wanted [2]IncidentConfiguredTest
	for i, input := range requested {
		key := entity.SourceKey{AgentID: input.AgentID, SourceRef: input.TestID, Kind: entity.PathAgent}
		if canonical, err := key.Normalize(); err != nil || canonical != key {
			return out, entity.ErrInvalidClaim
		}
		if canonical, err := validRegistryUUID(input.TestID); err != nil || canonical != input.TestID {
			return out, entity.ErrInvalidClaim
		}
		wanted[i] = IncidentConfiguredTest{ContextID: scope.ContextID, EntityID: router, AgentID: input.AgentID, TestID: input.TestID}
	}
	if maxBytes < 8192 {
		return out, ErrIncidentImpactBudget
	}
	member := IncidentImpactEntity{ContextID: scope.ContextID, EntityID: router}
	record, err := s.GetEntityContextInScope(ctx, sc, scope.ContextID)
	if err != nil {
		return out, err
	}
	if err := authorize(ctx, record, member, ""); err != nil {
		return out, err
	}
	generation, err := incidentImpactSourceGenerationInScope(ctx, sc)
	if err != nil {
		return out, err
	}
	rows, err := readIncidentConfiguredTests(ctx, sc, []string{scope.ContextID}, []string{router},
		map[string]IncidentImpactEntity{scope.ContextID + ":" + router: member}, generation, maxBytes, authorize, wanted[:])
	if err != nil {
		return out, err
	}
	if len(rows) != len(out) {
		return out, entity.ErrScopeMismatch
	}
	for _, row := range rows {
		if row.Type != "icmp" || row.PathBinding == nil || row.MeasurementIdentityUntil == nil {
			return [2]IncidentConfiguredTest{}, entity.ErrScopeMismatch
		}
		for i, want := range wanted {
			if clientReportTestKey(row) == clientReportTestKey(want) {
				out[i] = row
			}
		}
	}
	if out[0].TestID == "" || out[1].TestID == "" {
		return [2]IncidentConfiguredTest{}, entity.ErrScopeMismatch
	}
	return out, nil
}
