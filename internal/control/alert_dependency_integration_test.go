// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration || isolation

package control

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/ctlplne/probectl/internal/alert"
	"github.com/ctlplne/probectl/internal/cli"
	"github.com/ctlplne/probectl/internal/fairness"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/pkg/sdk"
)

func newDependencyAPIFixture(t *testing.T) (*roleExplanationAPIFixture, map[string]*alert.Rule) {
	t.Helper()
	f := newRoleExplanationAPIFixture(t)
	f.server.WithFairness(fairness.NewGate(fairness.DefaultPolicy(), nil)).WithFlowStore(flowstore.NewMemory())
	rules := map[string]*alert.Rule{}
	for _, tenant := range f.tenants {
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			for _, permission := range []string{permAlertRead, permAlertWrite, "topology.read", "test.read"} {
				if err := (store.Roles{}).AddPermission(ctx, sc, f.roles[tenant], permission); err != nil {
					return err
				}
			}
			rule, err := (store.AlertRules{}).Create(ctx, sc, alert.Rule{Name: "Owned reachability", Enabled: true, Metric: "probectl_probe_success", Type: alert.Threshold, Comparison: alert.EQ, Threshold: 0, Severity: alert.SeverityWarning})
			rules[tenant] = rule
			return err
		})
	}
	return f, rules
}

func TestTopologyDependencyConfigurationServesCurrentTwoTenantAuthority(t *testing.T) {
	f, rules := newDependencyAPIFixture(t)
	socket := httptest.NewTLSServer(f.server.Handler())
	t.Cleanup(socket.Close)
	ca := filepath.Join(t.TempDir(), "served-ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: socket.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	input := alert.DependencyPolicyInput{ContextID: f.contextID, FreshnessSeconds: 300}
	for _, tenant := range f.tenants {
		client := sdk.NewClient(socket.URL, sdk.WithHTTPClient(socket.Client()), sdk.WithToken(f.tokens[tenant]))
		configured, err := client.SetAlertDependencyPolicy(t.Context(), sdk.SetAlertDependencyPolicyRequest{Id: rules[tenant].ID, Body: &sdk.AlertDependencyPolicyInput{ContextId: input.ContextID, FreshnessSeconds: 300}})
		if err != nil || configured == nil || !configured.Configured || configured.Policy.ContextId != f.contextID || configured.RuleId != rules[tenant].ID {
			t.Fatal("verified HTTPS dependency configuration lost its owned rule/context", configured, err)
		}
		var stdout, stderr bytes.Buffer
		getenv := func(key string) string {
			return map[string]string{"PROBECTL_API_URL": socket.URL, "PROBECTL_API_TOKEN": f.tokens[tenant], "PROBECTL_CA_FILE": ca}[key]
		}
		if code := cli.RunWithStdin([]string{"--json", "alert", "dependency-policy", rules[tenant].ID}, getenv, bytes.NewReader(nil), &stdout, &stderr); code != 0 {
			t.Fatal("verified HTTPS dependency CLI read failed", code, stderr.String())
		}
		var state alert.DependencyPolicyState
		if err := json.Unmarshal(stdout.Bytes(), &state); err != nil || !state.Configured || state.RuleID != rules[tenant].ID || state.Policy == nil || *state.Policy != input {
			t.Fatal("CLI lost complete dependency configuration", state, err)
		}
	}
	request := func(tenant, headerTenant, method, id string, body any, want int) {
		t.Helper()
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		r, err := http.NewRequestWithContext(t.Context(), method, socket.URL+"/v1/alerts/rules/"+id+"/dependency-policy", bytes.NewReader(raw))
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set("Authorization", "Bearer "+f.tokens[tenant])
		r.Header.Set("X-Probectl-Tenant", headerTenant)
		r.Header.Set("Content-Type", "application/json")
		response, err := socket.Client().Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		if response.StatusCode != want {
			t.Fatal("dependency policy request returned an unexpected status", method, response.StatusCode, want)
		}
	}
	for i, tenant := range f.tenants {
		foreign := f.tenants[1-i]
		for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
			request(tenant, foreign, method, rules[tenant].ID, input, http.StatusUnauthorized)
			request(tenant, tenant, method, rules[foreign].ID, input, http.StatusNotFound)
		}
		// Stored ceilings cannot retain a permission withdrawn from the current
		// reader, and ordinary alert.write can still remove the policy.
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			_, err := sc.Q.Exec(ctx, `DELETE FROM role_permissions WHERE tenant_id=$1 AND role_id=$2 AND permission_key='topology.read'`, tenant, f.roles[tenant])
			return err
		})
		request(tenant, tenant, http.MethodGet, rules[tenant].ID, nil, http.StatusForbidden)
		request(tenant, tenant, http.MethodPut, rules[tenant].ID, input, http.StatusForbidden)
		request(tenant, tenant, http.MethodDelete, rules[tenant].ID, nil, http.StatusOK)
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			current, err := (store.AlertRules{}).Get(ctx, sc, rules[tenant].ID)
			if err != nil {
				return err
			}
			if !current.Enabled || current.HasDependencyPolicy || current.Metric != rules[tenant].Metric || current.Comparison != rules[tenant].Comparison || current.Threshold != rules[tenant].Threshold {
				t.Fatal("dependency clear changed detection or retained policy", current)
			}
			return nil
		})
	}
	t.Log("real-integration: app-role PG/FORCE-RLS, verified HTTPS SDK/CLI, foreign route denial, current grant withdrawal and write-only clear preserving detection; no dependency routing or physical-source claim")
}
