// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration || isolation

package control

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	gouuid "github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/alert"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func seedDependencyGraphFixture(t *testing.T, logs ...*slog.Logger) (*roleExplanationAPIFixture, map[string]*alert.Rule, map[string]*alert.DependencyGraphInput) {
	t.Helper()
	f, rules := newDependencyAPIFixture(t, logs...)
	graphs := map[string]*alert.DependencyGraphInput{}
	for _, tenant := range f.tenants {
		agent := gouuid.NewString() // registered agents are bound to one tenant
		rootTest, childTest := gouuid.NewString(), gouuid.NewString()
		graph := &alert.DependencyGraphInput{Nodes: []alert.DependencyNodeInput{
			{EntityID: f.routerID, AgentID: agent, TestID: rootTest, Parents: []string{}},
			{EntityID: f.otherRouter, AgentID: agent, TestID: childTest, Parents: []string{f.routerID}},
		}}
		graphs[tenant] = graph
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			if _, err := (store.Agents{}).Register(ctx, sc, agent, "dependency-agent", "127.0.0.1", "fixture", crypto.AgentSPIFFEID(tenant, agent), nil); err != nil {
				return err
			}
			registry := store.NewEntityRegistry(f.pool)
			for i, node := range graph.Nodes {
				target := []string{"192.0.2.1", "192.0.2.2"}[i]
				if _, err := sc.Q.Exec(ctx, `INSERT INTO tests(tenant_id,id,name,type,target,interval_seconds,timeout_seconds,params,enabled) VALUES($1,$2,'dependency ICMP '||$2::uuid::text,'icmp',$3,30,2,'{"allow_private_targets":"true"}',true)`, tenant, node.TestID, target); err != nil {
					return err
				}
				if err := registry.AssignPathTestContext(ctx, sc, node.TestID, f.contextID); err != nil {
					return err
				}
				if err := registry.AssignEntitySource(ctx, sc, entity.SourceKey{AgentID: agent, Kind: entity.PathAgent, SourceRef: node.TestID}, f.contextID, node.EntityID); err != nil {
					return err
				}
			}
			return nil
		})
	}
	return f, rules, graphs
}

func TestDependencyGraphServesCompleteCurrentTenantReferences(t *testing.T) {
	f, rules, graphs := seedDependencyGraphFixture(t)
	rootTest, childTest := graphs[f.tenants[0]].Nodes[0].TestID, graphs[f.tenants[1]].Nodes[1].TestID
	socket := httptest.NewTLSServer(f.server.Handler())
	t.Cleanup(socket.Close)
	call := func(tenant, method string, input *alert.DependencyGraphInput, want int) *alert.DependencyPolicyState {
		t.Helper()
		raw, err := json.Marshal(alert.DependencyPolicyInput{ContextID: f.contextID, FreshnessSeconds: 300, Graph: input})
		if err != nil {
			t.Fatal(err)
		}
		req, err := http.NewRequestWithContext(t.Context(), method, socket.URL+"/v1/alerts/rules/"+rules[tenant].ID+"/dependency-policy", strings.NewReader(string(raw)))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+f.tokens[tenant])
		req.Header.Set("Content-Type", "application/json")
		res, err := socket.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		body, err := io.ReadAll(res.Body)
		if err != nil {
			t.Fatal(err)
		}
		if res.StatusCode != want {
			t.Fatalf("%s graph status=%d want%d: %s", method, res.StatusCode, want, body)
		}
		if want != http.StatusOK {
			return nil
		}
		var state alert.DependencyPolicyState
		if err := json.Unmarshal(body, &state); err != nil {
			t.Fatal(err)
		}
		return &state
	}
	for _, tenant := range f.tenants {
		graph := graphs[tenant]
		for _, method := range []string{http.MethodPut, http.MethodGet} {
			state := call(tenant, method, graph, http.StatusOK)
			if !state.Configured || state.Policy == nil || !reflect.DeepEqual(state.Policy.Graph, graph) {
				t.Fatal("graph lost complete canonical references", state)
			}
		}
	}
	call(f.tenants[0], http.MethodPut, graphs[f.tenants[1]], http.StatusConflict)
	// A missing current reference must not borrow the sibling's registered
	// sources, despite equal canonical/context IDs and overlapping addresses.
	f.in(f.tenants[0], func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `DELETE FROM entity_path_test_contexts WHERE test_id=$1`, rootTest)
		return err
	})
	call(f.tenants[0], http.MethodGet, nil, http.StatusConflict)
	call(f.tenants[0], http.MethodPut, graphs[f.tenants[0]], http.StatusConflict)
	call(f.tenants[1], http.MethodGet, nil, http.StatusOK)
	// Source-specific ABAC applies to every node, beyond the context-level
	// decision. A current write grant can still clear without reading sources.
	f.in(f.tenants[1], func(ctx context.Context, sc tenancy.Scope) error {
		_, err := (store.ABACPolicies{}).Create(ctx, sc, auth.Policy{Name: "deny child source", Enabled: true, Effect: auth.PolicyDeny, Permission: "test.read", Resource: map[string]string{"test_id": childTest}, Priority: 100})
		return err
	})
	call(f.tenants[1], http.MethodGet, nil, http.StatusForbidden)
	f.in(f.tenants[1], func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `DELETE FROM entity_path_test_contexts WHERE test_id=$1`, childTest)
		return err
	})
	call(f.tenants[1], http.MethodGet, nil, http.StatusForbidden)
	call(f.tenants[1], http.MethodPut, graphs[f.tenants[1]], http.StatusForbidden)
	for _, tenant := range f.tenants {
		state := call(tenant, http.MethodDelete, nil, http.StatusOK)
		if state.Configured || state.Policy != nil {
			t.Fatal("write-only graph clear retained sources", state)
		}
	}
}
