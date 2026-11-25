// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type RoutingProbeTest struct {
	TestID  string `json:"test_id"`
	AgentID string `json:"agent_id"`
}

var ErrRoutingProbeSourcesBusy = errors.New("routing probe assignments are changing")

// LockRoutingProbeSourcesForPublication holds the exact test and assignment
// rows through the approval mutation. The enclosing publication already holds
// the tenant audit lock used by the evidence writer, so a concurrent late
// observation waits while the closed-window proof is checked and published.
func (s *EntityRegistry) LockRoutingProbeSourcesForPublication(ctx context.Context, sc tenancy.Scope, scope entity.Scope,
	router string, requested [2]RoutingProbeTest) error {
	if err := requireRoutingTransferReadSnapshot(ctx, sc); err != nil {
		return err
	}
	if err := requireRoutingCaptureReadSnapshot(ctx, sc); err != nil {
		return err
	}
	if canonical, err := scope.Normalize(); err != nil || canonical != scope || scope.TenantID != sc.Tenant.String() {
		return entity.ErrScopeMismatch
	}
	var locked int
	err := sc.Q.QueryRow(ctx, `WITH requested AS (
  SELECT * FROM unnest($4::uuid[],$5::text[]) AS key(test_id,agent_id)
), held AS (
  SELECT t.id FROM requested k
  JOIN tests t ON (t.tenant_id,t.id)=($1,k.test_id) AND t.enabled AND t.type='icmp'
  JOIN entity_test_contexts c ON (c.tenant_id,c.context_id,c.test_id)=($1,$2,t.id)
  JOIN entity_path_test_contexts p ON (p.tenant_id,p.context_id,p.test_id)=(c.tenant_id,c.context_id,c.test_id)
  JOIN entity_source_contexts m ON (m.tenant_id,m.context_id,m.anchor_entity_id,m.agent_id,m.source_kind,m.source_ref)
    =($1,$2,$3,k.agent_id,'path_agent',k.test_id::text)
  JOIN entity_agent_contexts a ON (a.tenant_id,a.context_id,a.agent_id)=(m.tenant_id,m.context_id,m.agent_id)
  ORDER BY t.id,k.agent_id FOR SHARE OF t,c,p,m,a NOWAIT
) SELECT count(*) FROM held`, scope.TenantID, scope.ContextID, router,
		[]string{requested[0].TestID, requested[1].TestID}, []string{requested[0].AgentID, requested[1].AgentID}).Scan(&locked)
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "55P03" {
		return ErrRoutingProbeSourcesBusy
	}
	if err != nil {
		return err
	}
	if locked != len(requested) {
		return entity.ErrScopeMismatch
	}
	return ctx.Err()
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
