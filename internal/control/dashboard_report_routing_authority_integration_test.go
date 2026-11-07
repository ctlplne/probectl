// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package control

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// Real current-user/credential/view authority and repeatable/locked report
// scopes in a one-connection application pool. The original routing selection
// is genuinely empty; this is not a physical sender or positive route proof.
func TestReportRoutingCurrentReaderKeepsOriginalReceiptAndSingleConnectionAuthority(t *testing.T) {
	f, rows, actors, at := newRoleFlowQueryFixture(t)
	config := f.pool.Config().Copy()
	config.MaxConns, config.MinConns = 1, 0
	pool, err := pgxpool.NewWithConfig(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	f.server.pool = pool
	f.server.WithFlowStore(rows.Memory)
	views := flow.NewPostgresQueryViewStore(pool, 0, audit.TenantRecord)
	f.server.WithFlowQueryViews(views)
	captures := map[string]*reportFlowCapture{}
	for _, tenant := range f.tenants {
		ctx, cancel := context.WithTimeout(auth.WithPrincipal(tenancy.WithTenant(t.Context(), tenancy.ID(tenant)), actors[tenant]), 20*time.Second)
		defer cancel()
		// Frozen readers ask only for this current access record. The current
		// saved definition is not a substitute for their original selectors.
		view, err := views.SaveQueryView(ctx, tenant, actors[tenant].UserID, flow.SaveQueryView{Definition: flow.QueryViewDefinition{Name: "Current routing reader access", Visibility: "private", Time: flow.QueryViewTime{Mode: "absolute"}, Plan: flow.QueryPlan{From: at.Add(-time.Minute), To: at.Add(time.Minute), GroupBy: []string{"protocol"}, Metrics: []flow.QueryMetric{{Measure: "bytes", Calculation: "total", Role: "primary"}}}}})
		if err != nil {
			t.Fatal(err)
		}
		var capture *reportFlowCapture
		err = tenancy.InTenantReadSnapshot(ctx, pool, func(ctx context.Context, sc tenancy.Scope) error {
			current, err := readCurrentUserAuthorityScope(ctx, sc, actors[tenant].UserID)
			if err != nil {
				return err
			}
			ctx, principal, err := current.requestContext(ctx, actors[tenant])
			if err != nil {
				return err
			}
			snapshot, err := f.server.loadFlowRoutingSnapshotInScope(ctx, sc, principal, flowstore.DefaultExplorerBudget(), func(context.Context) ([]flowstore.RoutingCaptureRead, error) {
				return []flowstore.RoutingCaptureRead{}, nil
			}, false)
			if err != nil {
				return err
			}
			proof, err := encodeFlowRoutingValidity(&flowstore.RoutingQueryProof{Digest: snapshot.digest, InputDigest: snapshot.inputDigest, Captures: snapshot.reads})
			if err != nil {
				return err
			}
			capture = &reportFlowCapture{TenantID: tenant, Permissions: []string{permAIQuery, permFlowRead, "entities.read"}, ContextsCaptured: true, ContextSources: true, Inputs: []reportFlowInput{{ID: view.ID, Version: view.Version, Period: "current", From: at.Add(-time.Minute), To: at.Add(time.Minute), RoutingSource: true, Routing: proof}}}
			return f.server.revalidateReportFlowCaptureScope(ctx, sc, actors[tenant], capture)
		})
		if err != nil {
			t.Fatal("current routing report opened a nested connection or lost its original empty source", err)
		}
		if err := tenancy.InTenant(ctx, pool, func(ctx context.Context, sc tenancy.Scope) error {
			return f.server.revalidateReportFlowCaptureScope(ctx, sc, actors[tenant], capture)
		}); err == nil {
			t.Fatal("report routing reader accepted a non-snapshot without publication lock")
		}
		if err := tenancy.InTenant(ctx, pool, func(ctx context.Context, sc tenancy.Scope) error {
			if err := audit.LockTenantStream(ctx, sc.Q, tenant); err != nil {
				return err
			}
			return f.server.revalidateReportFlowCaptureScope(ctx, sc, actors[tenant], capture)
		}); err != nil {
			t.Fatal("current report publication could not reuse its one connection", err)
		}
		changed := *capture
		changed.Inputs = append([]reportFlowInput(nil), capture.Inputs...)
		proof := *capture.Inputs[0].Routing
		proof.Digest = strings.Repeat("a", 64)
		if proof.Digest == capture.Inputs[0].Routing.Digest {
			proof.Digest = strings.Repeat("b", 64)
		}
		changed.Inputs[0].Routing = &proof
		if err := f.server.revalidateReportFlowCapture(ctx, actors[tenant], &changed); err == nil {
			t.Fatal("report reader reused changed original routing source proof")
		}
		limited := narrowPrincipalToScopes(auth.ClonePrincipal(actors[tenant]), []string{permAIQuery, permFlowRead})
		if err := f.server.revalidateReportFlowCapture(auth.WithPrincipal(ctx, limited), limited, capture); err == nil {
			t.Fatal("report routing reader widened its original credential ceiling")
		}
		captures[tenant] = capture
	}
	red, blue := f.tenants[0], f.tenants[1]
	f.in(red, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `DELETE FROM role_permissions WHERE tenant_id=$1 AND role_id=$2 AND permission_key='entities.read'`, red, f.roles[red])
		return err
	})
	ctx := auth.WithPrincipal(tenancy.WithTenant(t.Context(), tenancy.ID(red)), actors[red])
	if err := f.server.revalidateReportFlowCapture(ctx, actors[red], captures[red]); err == nil {
		t.Fatal("routing report retained revoked current user authority")
	}
	ctx = auth.WithPrincipal(tenancy.WithTenant(t.Context(), tenancy.ID(blue)), actors[blue])
	if err := f.server.revalidateReportFlowCapture(ctx, actors[blue], captures[blue]); err != nil {
		t.Fatal("routing report current-user revocation crossed tenant", err)
	}
	t.Log("real-integration: one-connection Postgres current user/credential/view access, original empty routing receipt, report publication lock and sibling isolation; positive router/flow facts remain separate")
}
