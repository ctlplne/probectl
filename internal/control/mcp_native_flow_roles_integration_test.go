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

	"github.com/ctlplne/probectl/internal/ai/mcp"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// Real TLS/bearer/native protocol/app-role PG. Telemetry and IX inputs are
// modeled, flow execution uses the production memory engine, not ClickHouse.
func TestNativeFlowRoleTLSKeepsWholeProvenanceAndCurrentAuthority(t *testing.T) {
	for _, wire := range []string{"2026-07-28", "2025-11-25"} {
		t.Run(wire, func(t *testing.T) {
			f, _, _, at := newRoleFlowQueryFixture(t)
			seedInterfaceRoleMCPConsent(f)
			call := interfaceRoleNativeTLSCaller(t, f, wire)
			a, b := f.tenants[0], f.tenants[1]
			plan := flow.QueryPlan{From: at.Add(-time.Minute), To: at.Add(time.Minute), GroupBy: []string{"in_if_role", "out_if_role"}, Metrics: []flow.QueryMetric{{Measure: "bytes", Calculation: "total", Role: "primary"}}}
			read := func(tenant string, want entity.InterfaceRole, total string) mcp.NativeFlowQueryResult {
				t.Helper()
				var got mcp.NativeFlowQueryResult
				call(tenant, "flow_explorer_query", map[string]any{"plan": plan}, &got, true)
				if string(got.Flow.RoleTenantID) != tenant || len(got.Flow.RoleDigest) != 64 || len(got.Flow.RoleSources) != 1 || len(got.Flow.Totals) != 1 || got.Flow.Totals[0].Value != total {
					t.Fatal("native role flow lost whole tenant totals or provenance", got.Flow.RoleTenantID, len(got.Flow.RoleDigest), len(got.Flow.RoleSources), got.Flow.Totals)
				}
				source := got.Flow.RoleSources[0]
				if string(source.TenantID) != tenant || string(source.ContextID) != f.contextID || string(source.RouterID) != f.routerID || string(source.InterfaceID) != f.interfaceID || source.Domain != 4294967295 || source.IfIndex != 7 || source.Role != string(want) || len(source.Sources) == 0 || !source.ValidUntil.After(time.Now()) {
					t.Fatal("native role flow changed canonical source identity", source)
				}
				if strings.Contains(source.Exporter, "192.0.2.1") || !strings.Contains(source.Exporter, "[ip:") {
					t.Fatal("native role flow escaped address redaction", source.Exporter)
				}
				groups := map[string]string{}
				for _, row := range got.Flow.Rows {
					fields := map[string]string{}
					for _, field := range row.Group {
						fields[field.Field] = field.Value
					}
					for _, metric := range row.Metrics {
						if metric.Metric == "bytes:total" {
							groups[fields["in_if_role"]+"/"+fields["out_if_role"]] = metric.Value
						}
					}
				}
				if tenant == a && (groups[string(want)+"/other"] != "100" || groups["other/other"] != "200") {
					t.Fatal("native role flow dropped unmatched rows or chose forged agent", groups)
				}
				if tenant == b && groups[string(want)+"/other"] != "900" {
					t.Fatal("native role flow lost paired same-address authority", groups)
				}
				return got
			}
			first := read(a, entity.InterfaceRoleTransit, "300")
			read(b, entity.InterfaceRoleBackbone, "900")
			for _, permission := range []string{"entities.read", "metrics.read", "events.read"} {
				f.in(a, func(ctx context.Context, sc tenancy.Scope) error {
					_, err := sc.Q.Exec(ctx, `DELETE FROM role_permissions WHERE tenant_id=$1 AND role_id=$2 AND permission_key=$3`, a, f.roles[a], permission)
					return err
				})
				call(a, "flow_explorer_query", map[string]any{"plan": plan}, nil, false)
				read(b, entity.InterfaceRoleBackbone, "900")
				f.in(a, func(ctx context.Context, sc tenancy.Scope) error {
					return (store.Roles{}).AddPermission(ctx, sc, f.roles[a], permission)
				})
			}
			saveCompleteRoleExplanationPolicy(f, a)
			complete := read(a, entity.InterfaceRoleBackbone, "300")
			if complete.Flow.RoleDigest == first.Flow.RoleDigest {
				t.Fatal("native role flow retained old policy generation")
			}
			if err := store.NewMCPTokens(f.pool).RevokeForUser(t.Context(), a, f.users[a]); err != nil {
				t.Fatal(err)
			}
			call(a, "flow_explorer_query", map[string]any{"plan": plan}, nil, false)
			read(b, entity.InterfaceRoleBackbone, "900")
		})
	}
}
