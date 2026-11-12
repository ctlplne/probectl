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
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"testing"

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
	f, rules, small := seedDependencyGraphFixture(t)
	policy := fairness.DefaultPolicy()
	policy.QueryConcurrency = 1
	f.server.WithFairness(fairness.NewGate(policy, nil))
	graph := &alert.DependencyGraphInput{}
	for i := range 20000 {
		id := gouuid.NewString()
		node := alert.DependencyNodeInput{EntityID: id, AgentID: small.Nodes[0].AgentID, TestID: id, Parents: []string{}}
		if i > 0 {
			node.Parents = []string{graph.Nodes[i-1].EntityID}
		}
		graph.Nodes = append(graph.Nodes, node)
	}
	rows, err := json.Marshal(graph.Nodes)
	if err != nil {
		t.Fatal(err)
	}
	for _, tenant := range f.tenants {
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			statements := []string{
				`INSERT INTO entities(tenant_id,context_id,id,kind,label) SELECT $1,$2,ref.entity_id,'device','dependency device' FROM jsonb_to_recordset($3::jsonb) AS ref(entity_id uuid)`,
				`INSERT INTO tests(tenant_id,id,name,type,target,interval_seconds,timeout_seconds,params,enabled) SELECT $1,ref.test_id,'dependency ICMP','icmp','127.0.0.1',30,2,'{"allow_private_targets":"true"}',true FROM jsonb_to_recordset($3::jsonb) AS ref(test_id uuid) WHERE $2::uuid IS NOT NULL`,
				`INSERT INTO entity_test_contexts(tenant_id,context_id,test_id) SELECT $1,$2,ref.test_id FROM jsonb_to_recordset($3::jsonb) AS ref(test_id uuid)`,
				`INSERT INTO entity_path_test_contexts(tenant_id,context_id,test_id,path_target) SELECT $1,$2,ref.test_id,'127.0.0.1' FROM jsonb_to_recordset($3::jsonb) AS ref(test_id uuid)`,
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
	input := alert.DependencyPolicyInput{ContextID: f.contextID, FreshnessSeconds: 300, Graph: graph}
	body, err := json.Marshal(input)
	if err != nil || len(body) <= 1<<20 {
		t.Fatal("full intended graph no longer exceeds the old decoder", len(body), err)
	}
	var sdkInput sdk.AlertDependencyPolicyInput
	if err := json.Unmarshal(body, &sdkInput); err != nil {
		t.Fatal(err)
	}
	for _, tenant := range f.tenants {
		client := sdk.NewClient(socket.URL, sdk.WithHTTPClient(socket.Client()), sdk.WithToken(f.tokens[tenant]))
		stored, err := client.SetAlertDependencyPolicy(t.Context(), sdk.SetAlertDependencyPolicyRequest{Id: rules[tenant].ID, Body: &sdkInput})
		if err != nil || stored == nil || !reflect.DeepEqual(stored.Policy.Graph, sdkInput.Graph) {
			t.Fatal("complete SDK graph was refused or changed", err)
		}
		var stdout, stderr bytes.Buffer
		getenv := func(key string) string {
			return map[string]string{"PROBECTL_API_URL": socket.URL, "PROBECTL_API_TOKEN": f.tokens[tenant], "PROBECTL_CA_FILE": ca}[key]
		}
		if code := cli.RunWithStdin([]string{"--json", "alert", "dependency-policy-set", rules[tenant].ID, "--body-file", "-"}, getenv, bytes.NewReader(body), &stdout, &stderr); code != 0 {
			t.Fatal("complete CLI graph failed", code, stderr.String())
		}
		var state alert.DependencyPolicyState
		if err := json.Unmarshal(stdout.Bytes(), &state); err != nil || state.Policy == nil || !reflect.DeepEqual(state.Policy.Graph, graph) {
			t.Fatal("CLI lost graph nodes or edges", err)
		}
	}
	seedInterfaceRoleMCPConsent(f)
	for _, wire := range []string{"2026-07-28", "2025-11-25"} {
		call := interfaceRoleNativeTLSCaller(t, f, wire)
		for _, tenant := range f.tenants {
			var state alert.DependencyPolicyState
			call(tenant, "alert_dependency_set", map[string]any{"rule_id": rules[tenant].ID, "input": input}, &state, true)
			if state.Policy == nil || !reflect.DeepEqual(state.Policy.Graph, graph) {
				t.Fatal("native graph lost complete source references or parent edges", wire)
			}
		}
	}
	t.Logf("real-integration: complete %d-node, %d-byte graph through verified HTTPS SDK, CLI and both native versions in paired RLS tenants; one query slot; seeded source configuration only", len(graph.Nodes), len(body))
}
