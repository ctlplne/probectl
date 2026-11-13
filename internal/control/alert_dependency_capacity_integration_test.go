// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package control

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	gouuid "github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/alert"
	"github.com/ctlplne/probectl/internal/cli"
	"github.com/ctlplne/probectl/internal/fairness"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/pkg/sdk"
)

// Real served configuration and Postgres/RLS; source assignments are seeded.
// This does not claim physical upstream failure or notification routing.
func TestDependencyGraphCompleteTwentyThousandNodeServedPopulation(t *testing.T) {
	f, rules, small := seedDependencyGraphFixture(t, slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})))
	// Drop this fixture's complete binding populations before parent cleanup,
	// avoiding a context-index scan for every test/device FK cascade. This is
	// fixture cleanup, not a tenant-lifecycle acceptance proof.
	t.Cleanup(func() {
		for _, query := range []string{
			`DELETE FROM entity_source_contexts WHERE tenant_id=ANY($1::uuid[])`,
			`DELETE FROM entity_path_test_contexts WHERE tenant_id=ANY($1::uuid[])`,
			`DELETE FROM entity_test_contexts WHERE tenant_id=ANY($1::uuid[])`,
		} {
			if _, err := f.pool.Exec(context.Background(), query, f.tenants); err != nil {
				t.Error(err)
			}
		}
	})
	policy := fairness.DefaultPolicy()
	policy.QueryConcurrency = 1
	f.server.WithFairness(fairness.NewGate(policy, nil))
	graph := &alert.DependencyGraphInput{}
	for i := range 20000 {
		id := gouuid.NewString()
		if i == 0 {
			id = "40000000-0000-4004-8000-abcdefabcdef" // canonical UUID with PAN-shaped digits
		}
		node := alert.DependencyNodeInput{EntityID: id, TestID: id, Parents: []string{}}
		if i > 0 {
			node.Parents = []string{graph.Nodes[i-1].EntityID}
		}
		graph.Nodes = append(graph.Nodes, node)
	}
	type seed struct {
		alert.DependencyNodeInput
		Target string `json:"target"`
	}
	graphs := map[string]*alert.DependencyGraphInput{}
	for _, tenant := range f.tenants {
		owned := &alert.DependencyGraphInput{Nodes: append([]alert.DependencyNodeInput(nil), graph.Nodes...)}
		seeds := make([]seed, len(owned.Nodes))
		for i := range owned.Nodes {
			owned.Nodes[i].AgentID = small[tenant].Nodes[0].AgentID
			owned.Nodes[i].TestID = gouuid.NewString()
			seeds[i] = seed{DependencyNodeInput: owned.Nodes[i], Target: fmt.Sprintf("2001:db8::%x", i+1)}
		}
		graphs[tenant] = owned
		rows, err := json.Marshal(seeds)
		if err != nil {
			t.Fatal(err)
		}
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			statements := []string{
				`INSERT INTO entities(tenant_id,context_id,id,kind,label) SELECT $1,$2,ref.entity_id,'device','dependency device' FROM jsonb_to_recordset($3::jsonb) AS ref(entity_id uuid)`,
				`INSERT INTO tests(tenant_id,id,name,type,target,interval_seconds,timeout_seconds,params,enabled) SELECT $1,ref.test_id,'dependency ICMP '||ref.test_id::text,'icmp',ref.target,30,2,'{"allow_private_targets":"true"}',true FROM jsonb_to_recordset($3::jsonb) AS ref(test_id uuid,target text) WHERE $2::uuid IS NOT NULL`,
				`INSERT INTO entity_test_contexts(tenant_id,context_id,test_id) SELECT $1,$2,ref.test_id FROM jsonb_to_recordset($3::jsonb) AS ref(test_id uuid)`,
				`INSERT INTO entity_path_test_contexts(tenant_id,context_id,test_id,path_target) SELECT $1,$2,ref.test_id,ref.target FROM jsonb_to_recordset($3::jsonb) AS ref(test_id uuid,target text)`,
				`INSERT INTO entity_source_contexts(tenant_id,context_id,agent_id,source_kind,source_ref,anchor_entity_id) SELECT $1,$2,ref.agent_id::text,'path_agent',ref.test_id::text,ref.entity_id FROM jsonb_to_recordset($3::jsonb) AS ref(agent_id uuid,test_id uuid,entity_id uuid)`,
			}
			for _, statement := range statements {
				if _, err := sc.Q.Exec(ctx, statement, tenant, f.contextID, rows); err != nil {
					return err
				}
			}
			return nil
		})
	}
	socket := httptest.NewTLSServer(f.server.Handler())
	t.Cleanup(socket.Close)
	ca := filepath.Join(t.TempDir(), "served-ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: socket.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	bodyBytes := 0
	for _, tenant := range f.tenants {
		graph := graphs[tenant]
		input := alert.DependencyPolicyInput{ContextID: f.contextID, FreshnessSeconds: 300, Graph: graph}
		body, err := json.Marshal(input)
		if err != nil || len(body) <= 1<<20 {
			t.Fatal("full intended graph no longer exceeds the old decoder", len(body), err)
		}
		bodyBytes = len(body)
		var sdkInput sdk.AlertDependencyPolicyInput
		if err := json.Unmarshal(body, &sdkInput); err != nil {
			t.Fatal(err)
		}
		client := sdk.NewClient(socket.URL, sdk.WithHTTPClient(socket.Client()), sdk.WithToken(f.tokens[tenant]))
		started := time.Now()
		stored, err := client.SetAlertDependencyPolicy(t.Context(), sdk.SetAlertDependencyPolicyRequest{Id: rules[tenant].ID, Body: &sdkInput})
		if err != nil || stored == nil || !reflect.DeepEqual(stored.Policy.Graph, sdkInput.Graph) {
			t.Fatal("complete SDK graph was refused or changed", err)
		}
		t.Log("complete SDK graph passed", tenant, "elapsed", time.Since(started))
		var stdout, stderr bytes.Buffer
		getenv := func(key string) string {
			return map[string]string{"PROBECTL_API_URL": socket.URL, "PROBECTL_API_TOKEN": f.tokens[tenant], "PROBECTL_CA_FILE": ca}[key]
		}
		started = time.Now()
		if code := cli.RunWithStdin([]string{"--json", "alert", "dependency-policy-set", rules[tenant].ID, "--body-file", "-"}, getenv, bytes.NewReader(body), &stdout, &stderr); code != 0 {
			t.Fatal("complete CLI graph failed", code, stderr.String())
		}
		var state alert.DependencyPolicyState
		if err := json.Unmarshal(stdout.Bytes(), &state); err != nil || state.Policy == nil || !reflect.DeepEqual(state.Policy.Graph, graph) {
			t.Fatal("CLI lost graph nodes or edges", err)
		}
		t.Log("complete CLI graph passed", tenant, "elapsed", time.Since(started))
	}
	seedInterfaceRoleMCPConsent(f)
	for _, wire := range []string{"2026-07-28", "2025-11-25"} {
		call := interfaceRoleNativeTLSCaller(t, f, wire)
		for _, tenant := range f.tenants {
			graph := graphs[tenant]
			input := alert.DependencyPolicyInput{ContextID: f.contextID, FreshnessSeconds: 300, Graph: graph}
			var state alert.DependencyPolicyState
			call(tenant, "alert_dependency_set", map[string]any{"rule_id": rules[tenant].ID, "input": input}, &state, true)
			if state.Policy == nil || !reflect.DeepEqual(state.Policy.Graph, graph) {
				if state.Policy != nil && state.Policy.Graph != nil {
					t.Logf("native graph count: got %d, want %d", len(state.Policy.Graph.Nodes), len(graph.Nodes))
					for i := range min(len(state.Policy.Graph.Nodes), len(graph.Nodes)) {
						if !reflect.DeepEqual(state.Policy.Graph.Nodes[i], graph.Nodes[i]) {
							t.Logf("first mismatched node %d: got %+v, want %+v", i, state.Policy.Graph.Nodes[i], graph.Nodes[i])
							break
						}
					}
				}
				t.Fatal("native graph lost complete source references or parent edges", wire)
			}
			t.Log("complete native graph passed", wire, tenant)
		}
	}
	t.Logf("real-integration: complete %d-node, %d-byte graph through verified HTTPS SDK, CLI and both native versions in paired RLS tenants; one query slot; seeded source configuration only", len(graph.Nodes), bodyBytes)
}
