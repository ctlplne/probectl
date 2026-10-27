// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package store

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/tenancy"
)

// TestCoverageCandidatesCrossTenantIsolation proves the relational agent×test
// join is tenant constrained at the storage layer. Distinct labels, names, and
// targets make any leak immediately visible.
func TestCoverageCandidatesCrossTenantIsolation(t *testing.T) {
	ctx := context.Background()
	pool := setup(ctx, t)
	defer pool.Close()

	type fixture struct {
		tenantID string
		testName string
		target   string
		region   string
		site     string
	}
	makeFixture := func(prefix string) fixture {
		suffix := fmt.Sprintf("%d", time.Now().UnixNano())
		tenant, err := NewTenants(pool).Create(ctx, prefix+"-"+suffix, prefix)
		if err != nil {
			t.Fatal(err)
		}
		f := fixture{
			tenantID: tenant.ID, testName: prefix + "-test",
			target: prefix + ".example:443", region: prefix + "-region", site: prefix + "-site",
		}
		inTenant(ctx, t, pool, tenant.ID, func(ctx context.Context, scope tenancy.Scope) error {
			if _, err := (Tests{}).Create(ctx, scope, TestInput{
				Name: f.testName, Type: "tcp", Target: f.target,
				IntervalSeconds: 60, TimeoutSeconds: 5, Enabled: true,
			}); err != nil {
				return err
			}
			agentID := covUUID(t)
			_, err := (Agents{}).RegisterWithLabels(
				ctx, scope, agentID, prefix+"-agent", prefix+"-host", "0.1.0",
				"spiffe://probectl/tenant/"+tenant.ID+"/agent/"+agentID,
				[]string{"tcp"}, map[string]string{"region": f.region, "site": f.site},
			)
			return err
		})
		return f
	}

	a := makeFixture("coverage-a")
	b := makeFixture("coverage-b")
	registerCollector := func(tenantID, plane string) {
		t.Helper()
		inTenant(ctx, t, pool, tenantID, func(ctx context.Context, scope tenancy.Scope) error {
			agentID := covUUID(t)
			_, err := (Agents{}).Register(
				ctx, scope, agentID, plane+"-"+agentID, plane+"-"+agentID, "0.1.0",
				"spiffe://probectl/tenant/"+tenantID+"/agent/"+agentID,
				[]string{"collector", plane},
			)
			return err
		})
	}
	registerCollector(a.tenantID, "flow")
	registerCollector(b.tenantID, "bgp")
	registerCollector(b.tenantID, "bgp")
	inTenant(ctx, t, pool, a.tenantID, func(ctx context.Context, scope tenancy.Scope) error {
		rows, err := (Agents{}).CoverageCandidates(ctx, scope, 10)
		if err != nil {
			return err
		}
		if len(rows) != 1 {
			t.Fatalf("rows = %d, want 1", len(rows))
		}
		got := rows[0]
		if got.TestName != a.testName || got.Target != a.target || got.Region != a.region || got.Site != a.site {
			t.Fatalf("tenant A row = %+v", got)
		}
		if got.TestName == b.testName || got.Target == b.target || got.Region == b.region || got.Site == b.site {
			t.Fatalf("tenant B labels/test/target leaked into tenant A: %+v", got)
		}
		producers, err := (Agents{}).CoverageProducers(ctx, scope)
		if err != nil {
			return err
		}
		if producers.Flow != 1 || producers.Routing != 0 {
			t.Fatalf("tenant A producer counts = %+v, want one flow and no tenant B routing collectors", producers)
		}
		return nil
	})
}

// Exact evidence may recover an incompatible owned vantage, but cannot pull
// another tenant's agent or test through the relational boundary.
func TestCoverageHistoricalEvidenceCrossTenantIsolation(t *testing.T) {
	ctx := context.Background()
	pool := setup(ctx, t)
	defer pool.Close()
	type fixture struct{ tenant, test, agent string }
	makeFixture := func(prefix string) fixture {
		tenant, err := NewTenants(pool).Create(ctx, fmt.Sprintf("%s-%d", prefix, time.Now().UnixNano()), prefix)
		if err != nil {
			t.Fatal(err)
		}
		f := fixture{tenant: tenant.ID, agent: covUUID(t)}
		inTenant(ctx, t, pool, f.tenant, func(ctx context.Context, s tenancy.Scope) error {
			test, err := (Tests{}).Create(ctx, s, TestInput{Name: prefix, Type: "dns", Target: "shared.example", IntervalSeconds: 30, TimeoutSeconds: 5, Enabled: true})
			if err != nil {
				return err
			}
			f.test = test.ID
			_, err = (Agents{}).RegisterWithLabels(ctx, s, f.agent, prefix, prefix, "0.1.0",
				"spiffe://probectl/tenant/"+f.tenant+"/agent/"+f.agent, []string{"browser"}, map[string]string{"site": prefix})
			return err
		})
		return f
	}
	a, b := makeFixture("history-a"), makeFixture("history-b")
	for _, own := range []fixture{a, b} {
		foreign := b
		if own == b {
			foreign = a
		}
		inTenant(ctx, t, pool, own.tenant, func(ctx context.Context, s tenancy.Scope) error {
			refs := []CoverageEvidence{
				{TestID: own.test, AgentID: own.agent, ProbeFamily: "dns", Target: "shared.example"},
				{TestID: own.test, AgentID: foreign.agent, ProbeFamily: "dns", Target: "shared.example"},
				{TestID: foreign.test, AgentID: foreign.agent, ProbeFamily: "dns", Target: "shared.example"},
			}
			rows, err := (Agents{}).CoverageCandidates(ctx, s, 10, refs...)
			if err != nil {
				return err
			}
			if len(rows) != 1 || rows[0].AgentID != own.agent || rows[0].TestID != own.test || !rows[0].EvidenceOnly {
				t.Fatalf("historical owned candidate or isolation failed: %+v", rows)
			}
			for _, bad := range []CoverageEvidence{
				{TestID: own.test, AgentID: own.agent, ProbeFamily: "http", Target: "shared.example"},
				{TestID: own.test, AgentID: own.agent, ProbeFamily: "dns", Target: "different.example"},
				{TestID: own.test, AgentID: foreign.agent, ProbeFamily: "dns", Target: "shared.example"},
			} {
				rows, err = (Agents{}).CoverageCandidates(ctx, s, 10, bad)
				if err != nil {
					return err
				}
				if len(rows) != 1 || rows[0].AgentID != "" || rows[0].EvidenceOnly {
					t.Fatalf("unmatched evidence gained a vantage: %+v", rows)
				}
			}
			return nil
		})
	}
}
