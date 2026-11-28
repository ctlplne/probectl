// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration || isolation

package control

import (
	"context"
	"errors"
	"testing"
	"time"

	gouuid "github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/path"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/pathstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestCarrierSLAPathContextKeepsCircuitAndTenant(t *testing.T) {
	f := newRoleExplanationAPIFixture(t)
	paths := pathstore.NewMemory()
	batch := pathstore.NewBatchingSaver(paths, nil, time.Hour, 64)
	t.Cleanup(func() { _ = batch.Close() })
	f.server.pathStore = batch
	agreement := flow.CapacityAgreement{Definition: flow.CapacityAgreementDefinition{
		Target: flow.CapacityTarget{Kind: "interface", ContextID: f.contextID, InterfaceID: f.interfaceID},
	}}
	start := time.Now().UTC().Add(-time.Hour)
	period := flow.CapacityBillingPeriod{From: start, To: start.Add(2 * time.Hour)}
	const target = "198.51.100.10"
	type lane struct {
		tenant      string
		actor       *auth.Principal
		sources     []store.IncidentConfiguredTest
		roundID     string
		requirement carrierSLAReportRequirement
	}
	var lanes [2]lane
	for i, tenant := range f.tenants {
		current := &lanes[i]
		current.tenant = tenant
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			if err := (store.Roles{}).AddPermission(ctx, sc, f.roles[tenant], permTestRead); err != nil {
				return err
			}
			authority, err := readCurrentUserAuthorityScope(ctx, sc, f.users[tenant])
			if err == nil {
				current.actor = auth.ClonePrincipal(authority.principal)
			}
			return err
		})
		for _, device := range []string{f.routerID, f.otherRouter} {
			agent := gouuid.NewString()
			definition := seedVerdictCarrierTest(t, f, tenant, agent, target)
			f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
				registry := store.NewEntityRegistry(f.pool)
				ref := entity.SourceKey{AgentID: agent, Kind: entity.PathAgent, SourceRef: definition.ID}
				if err := registry.AssignEntitySource(ctx, sc, ref, f.contextID, device); err != nil {
					return err
				}
				binding, err := registry.PathTestBindingInScope(ctx, sc, definition.ID)
				if err != nil {
					return err
				}
				current.sources = append(current.sources, store.IncidentConfiguredTest{
					TenantID: tenant, ContextID: f.contextID, EntityID: device, TestID: definition.ID, AgentID: agent,
					CurrentSince: binding.AssignedAt, Target: target, PathBinding: &binding,
				})
				return nil
			})
		}
		ctx, roundID, err := pathstore.NewDiscoveryRound(tenancy.WithTenant(t.Context(), tenancy.ID(tenant)))
		if err != nil {
			t.Fatal(err)
		}
		observedAt := f.observedAt(tenant)
		ctx = pathstore.WithDiscoveryCompletedAt(pathstore.WithDiscoveryStartedAt(ctx, observedAt), observedAt.Add(time.Microsecond))
		ctx = pathstore.WithDiscoveryTest(ctx, current.sources[0].TestID)
		if err := batch.Save(ctx, tenant, &path.Path{Target: target, TargetIP: target, Hops: []path.Hop{
			{TTL: 1, Nodes: []path.HopNode{{IP: "192.0.2.1", Geo: &path.HopGeo{City: "private operator location"}}}},
		}}); err != nil {
			t.Fatal(err)
		}
		current.roundID = roundID
		current.requirement.Period = period
		evidenceBefore := observedAt.Add(time.Second)
		current.requirement.EvidenceBefore = &evidenceBefore
		later, _, err := pathstore.NewDiscoveryRound(tenancy.WithTenant(t.Context(), tenancy.ID(tenant)))
		if err != nil {
			t.Fatal(err)
		}
		later = pathstore.WithDiscoveryCompletedAt(pathstore.WithDiscoveryStartedAt(later, observedAt.Add(time.Millisecond)), evidenceBefore)
		later = pathstore.WithDiscoveryTest(later, current.sources[0].TestID)
		if err := batch.Save(later, tenant, &path.Path{Target: target, TargetIP: target}); err != nil {
			t.Fatal(err)
		}
		// Neither a different test using the same target nor a stored round with
		// unknown origin can be relabeled as this circuit's trace.
		for _, testID := range []string{current.sources[1].TestID, ""} {
			other := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
			other = pathstore.WithDiscoveryCompletedAt(pathstore.WithDiscoveryStartedAt(other, observedAt), observedAt.Add(time.Microsecond))
			other = pathstore.WithDiscoveryTest(other, testID)
			if err := batch.Save(other, tenant, &path.Path{Target: target, TargetIP: target}); err != nil {
				t.Fatal(err)
			}
		}
	}

	batch.Flush(t.Context())
	// A report holds a database transaction and must leave pending writes
	// for the normal batch flush, including writes from the other tenant.
	for _, current := range lanes {
		start := current.requirement.EvidenceBefore.Add(-time.Millisecond)
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(current.tenant))
		ctx = pathstore.WithDiscoveryStartedAt(ctx, start)
		ctx = pathstore.WithDiscoveryCompletedAt(ctx, start.Add(time.Microsecond))
		ctx = pathstore.WithDiscoveryTest(ctx, current.sources[0].TestID)
		if err := batch.Save(ctx, current.tenant, &path.Path{Target: target, TargetIP: target}); err != nil {
			t.Fatal(err)
		}
	}

	for i := range lanes {
		current := &lanes[i]
		f.in(current.tenant, func(ctx context.Context, sc tenancy.Scope) error {
			rounds, err := f.server.carrierSLAPathRounds(ctx, current.tenant, current.sources[0], current.requirement.evidencePeriod(), nil, 4096, nil)
			if len(rounds) != 0 || !errors.Is(err, store.ErrClientReportBudget) {
				t.Fatal("path storage admission did not refuse the complete report read", err)
			}
			got, err := f.server.captureCarrierSLAPathOriginals(ctx, sc, current.actor, agreement, current.sources, &current.requirement, 8<<20, nil)
			if err != nil || len(got) != 1 || len(current.requirement.Paths) != 1 ||
				got[0].TestID != current.sources[0].TestID || got[0].RoundID != current.roundID ||
				got[0].Path.Vantage != path.VantageControlPlane || got[0].Path.Hops[0].Nodes[0].Geo != nil {
				t.Fatal("carrier context mixed circuits, tenants or observation windows, or retained private geography", err)
			}
			return f.server.revalidateCarrierSLAPaths(ctx, sc, current.actor, agreement, current.sources, current.requirement, 8<<20)
		})
	}
	batch.Flush(t.Context())
	deleted := lanes[0]
	if count, _, err := paths.DeleteTenant(tenancy.WithTenant(t.Context(), tenancy.ID(deleted.tenant)), deleted.tenant); err != nil || count != 5 {
		t.Fatal("remove the owned rounds from the first tenant", count, err)
	}
	for i, current := range lanes {
		f.in(current.tenant, func(ctx context.Context, sc tenancy.Scope) error {
			err := f.server.revalidateCarrierSLAPaths(ctx, sc, current.actor, agreement, current.sources, current.requirement, 8<<20)
			if (err != nil) != (i == 0) {
				t.Fatal("path removal kept the old artifact readable or affected its sibling", err)
			}
			return nil
		})
	}
}
