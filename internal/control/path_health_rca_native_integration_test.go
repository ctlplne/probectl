// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package control

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/ctlplne/probectl/internal/ai"
	"github.com/ctlplne/probectl/internal/config"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestPathHealthRCANativeTLSAndPersistentStdioKeepCurrentOwnedCitations(t *testing.T) {
	for _, wire := range []string{"2026-07-28", "2025-11-25"} {
		t.Run(wire, func(t *testing.T) { provePathHealthRCANative(t, wire) })
	}
}

func provePathHealthRCANative(t *testing.T, wire string) {
	t.Helper()
	proof := newPathHealthAPIFixture(t)
	f := proof.fixture
	model := &pathHealthRCAModel{}
	f.server.analyzer = ai.NewAnalyzer(buildEngineWithPolicyLoader(f.server.cfg, f.pool, f.server.aiPolicyLoader(), f.server.aiSources()), ai.WithModel(model), ai.WithMaxEvidence(1))
	for _, tenant := range f.tenants {
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			return (store.Roles{}).AddPermission(ctx, sc, f.roles[tenant], "ai.query")
		})
	}
	seedInterfaceRoleMCPConsent(f)
	call := interfaceRoleNativeTLSCaller(t, f, wire)
	args := func(tenant string) map[string]any {
		input := map[string]any{"test_id": proof.tests[tenant], "question": "Explain observed path errors and utilization without claiming causation."}
		for key, value := range proof.windows[tenant] {
			if key != "include_health" {
				input[key] = value[0]
			}
		}
		return input
	}
	check := func(tenant string, answer ai.Answer) {
		t.Helper()
		if answer.Tenant != tenant || len(answer.Evidence) != 1 || !answer.RootCauseGrounded || len(answer.RootCauseCitations) == 0 || answer.RootCauseCitations[0].EvidenceID != answer.Evidence[0].ID {
			t.Fatal("native path explanation lost its owned source or exact citations")
		}
		item := answer.Evidence[0]
		if item.Ref != "/path?test_id="+proof.tests[tenant] || item.Fields["path_test_id"] != proof.tests[tenant] {
			t.Fatal("native path explanation changed its canonical source reference")
		}
		raw, err := json.Marshal(item.Fields["path_health"])
		if err != nil {
			t.Fatal(err)
		}
		var health pathHealthResult
		if err := json.Unmarshal(raw, &health); err != nil || len(health.Items) != 2 || health.Items[0].Health == nil || len(health.Items[0].Health.Counters) != len(pathHealthMetricNames) {
			t.Fatal("native explanation lost complete original path observations", err)
		}
		counter := health.Items[0].Health.Counters[0]
		if health.TestID != proof.tests[tenant] || counter.PreviousValue != "9007199254740993" || counter.UtilizationNumerator != "98" || counter.CaptureKey == "" || health.Items[0].IP == "10.42.0.2" {
			t.Fatal("native explanation changed original metadata or bypassed source-text redaction")
		}
	}
	for _, tenant := range f.tenants {
		var answer ai.Answer
		call(tenant, "path_interface_health_explain", args(tenant), &answer, true)
		check(tenant, answer)
	}
	a, b := f.tenants[0], f.tenants[1]
	foreign := args(a)
	foreign["test_id"] = proof.tests[b]
	before := model.calls
	call(a, "path_interface_health_explain", foreign, nil, false)
	if model.calls != before {
		t.Fatal("foreign path ID reached synthesis")
	}
	for _, key := range []string{"tenant_id", "device_id", "capture_key"} {
		forged := args(a)
		forged[key] = proof.tests[b]
		call(a, "path_interface_health_explain", forged, nil, false)
	}
	cfg := &config.Config{AIRedactIPs: true, AIRedactHostnames: true, AIRedactPII: true}
	server := NewMCPServerWithPolicyLoader(cfg, f.server.log, f.pool, f.server.pathStore, 0, NewAIEgressGate(cfg, f.server.log, f.pool), nil, nil, f.server.MCPPolicyLoader(), AISources{NativeFlow: f.server})
	authenticator := NewMCPAuthenticator(f.pool, NewTenantStatusCache(f.pool, 0), false)
	streams := map[string]*interfaceRoleStdioClient{}
	for _, tenant := range f.tenants {
		streams[tenant] = openInterfaceRoleStdio(t, server, authenticator, f.tokens[tenant], wire)
		var answer ai.Answer
		streams[tenant].call(t, wire, "path_interface_health_explain", args(tenant), &answer, true)
		check(tenant, answer)
	}
	model.after = func() {
		model.after = nil
		f.in(a, func(ctx context.Context, sc tenancy.Scope) error {
			_, err := sc.Q.Exec(ctx, `DELETE FROM role_permissions WHERE tenant_id=$1 AND role_id=$2 AND permission_key='metrics.read'`, a, f.roles[a])
			return err
		})
	}
	streams[a].call(t, wire, "path_interface_health_explain", args(a), nil, false)
	var sibling ai.Answer
	streams[b].call(t, wire, "path_interface_health_explain", args(b), &sibling, true)
	check(b, sibling)
	f.in(a, func(ctx context.Context, sc tenancy.Scope) error {
		return (store.Roles{}).AddPermission(ctx, sc, f.roles[a], "metrics.read")
	})
	model.after = func() {
		model.after = nil
		if err := store.NewMCPTokens(f.pool).RevokeForUser(t.Context(), a, f.users[a]); err != nil {
			t.Fatal(err)
		}
	}
	call(a, "path_interface_health_explain", args(a), nil, false)
	call(b, "path_interface_health_explain", args(b), &sibling, true)
	check(b, sibling)
	t.Log("real-integration: paired PG/RLS, verified TLS/native framing and authenticated persistent stdio, original citations and current role/exact bearer withdrawal; path/SNMP/history/model are modeled, physical lab proof remains owed")
}
