// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// Simulation: exercise the production memory engine and native projection.
// Actual authenticated native protocol/current-source proof is separate.
func nativeRoleProjectionFixture(t *testing.T, tenant string, role entity.InterfaceRole) flowstore.PlanResult {
	t.Helper()
	at := time.Now().UTC().Truncate(time.Microsecond)
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
	sources := []flowstore.InterfaceRoleProjection{{Scope: entity.Scope{TenantID: tenant, ContextID: "22222222-2222-4222-8222-222222222222"}, RouterID: "33333333-3333-4333-8333-333333333333", InterfaceID: "40000000-0000-4004-8000-abcdefabcdef", Exporter: "192.0.2.1", Protocol: "ipfix", Domain: 4294967295, IfIndex: 7, Role: role, Reason: "provider_asn", Sources: []string{"policy/40000000-0000-4004-8000-abcdefabcdef/4111111111111111", "evidence/owned"}, ValidUntil: at.Add(time.Hour)}}
	lookup, err := flowstore.NewInterfaceRoleQueryData(ctx, tenant, at, sources, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	memory := flowstore.NewMemory()
	if err := memory.Insert(ctx, []flowstore.Row{{TenantID: tenant, AgentID: "untrusted-agent", Exporter: "192.0.2.1", Protocol: "ipfix", ObsDomain: 4294967295, InIf: 7, OutIf: 99, TS: at, BytesScaled: 100}}); err != nil {
		t.Fatal(err)
	}
	result, err := memory.ExplorePlan(ctx, flowstore.PlanQuery{TenantID: tenant, Roles: lookup, Plan: flow.QueryPlan{From: at.Add(-time.Minute), To: at.Add(time.Minute), View: "table", GroupBy: []string{"in_if_role", "out_if_role"}, Metrics: []flow.QueryMetric{{Measure: "bytes", Calculation: "total", Role: "primary"}}}})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestNativeFlowRoleProjectionRetainsCompleteTenantProvenance(t *testing.T) {
	for _, tenant := range []string{"11111111-1111-4111-8111-111111111111", "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"} {
		t.Run(tenant, func(t *testing.T) {
			source := nativeRoleProjectionFixture(t, tenant, entity.InterfaceRoleTransit)
			projected, err := projectNativeFlow(source, tenant)
			if err != nil {
				t.Fatal(err)
			}
			check := func() {
				t.Helper()
				raw, err := json.Marshal(projected)
				if err != nil {
					t.Fatal(err)
				}
				var got struct {
					Tenant  string                              `json:"role_tenant_id"`
					Digest  string                              `json:"role_digest"`
					Sources []flowstore.InterfaceRoleProjection `json:"role_sources"`
				}
				if err := json.Unmarshal(raw, &got); err != nil {
					t.Fatal(err)
				}
				if got.Tenant != tenant || got.Digest != source.RoleDigest || !reflect.DeepEqual(got.Sources, source.RoleSources) {
					t.Fatal("native flow projection lost complete tenant role provenance", string(raw))
				}
			}
			check()
			before, _ := json.Marshal(projected)
			source.RoleSources[0].Sources[0] = "changed upstream backing slice"
			after, _ := json.Marshal(projected)
			if string(before) != string(after) {
				t.Fatal("native role result aliases mutable source metadata")
			}
		})
	}
}

func TestNativeFlowRoleProjectionRefusesForeignMissingStaleOrChangedIdentity(t *testing.T) {
	const tenant = "11111111-1111-4111-8111-111111111111"
	for name, mutate := range map[string]func(*flowstore.PlanResult){
		"foreign envelope":         func(r *flowstore.PlanResult) { r.RoleTenantID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa" },
		"foreign source":           func(r *flowstore.PlanResult) { r.RoleSources[0].TenantID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa" },
		"missing digest":           func(r *flowstore.PlanResult) { r.RoleDigest = "" },
		"changed digest":           func(r *flowstore.PlanResult) { r.RoleDigest = strings.Repeat("0", 64) },
		"changed provenance":       func(r *flowstore.PlanResult) { r.RoleSources[0].Sources[0] = "evidence/changed" },
		"expired":                  func(r *flowstore.PlanResult) { r.RoleSources[0].ValidUntil = time.Now().Add(-time.Second) },
		"missing sources":          func(r *flowstore.PlanResult) { r.RoleSources = nil },
		"unexpected role metadata": func(r *flowstore.PlanResult) { r.Query.GroupBy = []string{"protocol"} },
	} {
		t.Run(name, func(t *testing.T) {
			r := nativeRoleProjectionFixture(t, tenant, entity.InterfaceRoleTransit)
			mutate(&r)
			if _, err := projectNativeFlow(r, tenant); err == nil {
				t.Fatal("native role projection admitted foreign or inconsistent generation", name)
			}
		})
	}
	a := nativeRoleProjectionFixture(t, tenant, entity.InterfaceRoleTransit)
	b := nativeRoleProjectionFixture(t, tenant, entity.InterfaceRoleCustomer)
	if _, err := projectNativeFlowComparison(explorerComparisonResult{Flow: &flowExplorerComparisonData{Current: a, Previous: b}}, tenant); err == nil {
		t.Fatal("native role comparison admitted different current generations")
	}
}

func TestNativeFlowRoleProjectionHonorsCancellationAndExistingTenantScope(t *testing.T) {
	const tenant = "11111111-1111-4111-8111-111111111111"
	source := nativeRoleProjectionFixture(t, tenant, entity.InterfaceRoleTransit)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := projectNativeFlow(source, tenant, nativeFlowProjectionOptions{ctx: ctx, budget: flowstore.DefaultExplorerBudget()}); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled native role projection retained work", err)
	}
	foreign := tenancy.WithTenant(t.Context(), tenancy.ID("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"))
	if _, err := projectNativeFlow(source, tenant, nativeFlowProjectionOptions{ctx: foreign, budget: flowstore.DefaultExplorerBudget()}); err == nil {
		t.Fatal("native role projection overwrote an existing foreign tenant scope")
	}
	ctx = tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
	if _, err := projectNativeFlow(source, tenant, nativeFlowProjectionOptions{ctx: ctx, budget: flowstore.DefaultExplorerBudget()}); err != nil {
		t.Fatal("native role projection lost the authorized request context", err)
	}
}
