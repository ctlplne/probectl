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
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/alert"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/cli"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/tsdb"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestDependencyWorkflowExplainsCurrentTenantHoldAndWithdrawals(t *testing.T) {
	d := seedDependencyRoutingFixture(t)
	socket := httptest.NewTLSServer(d.f.server.Handler())
	t.Cleanup(socket.Close)
	ca := filepath.Join(t.TempDir(), "workflow-ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: socket.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	for _, tenant := range d.f.tenants {
		readerToken, readerRole := dependencyWorkflowReader(t, d, tenant)
		var series []tsdb.Series
		for _, node := range d.graphs[tenant].Nodes {
			series = append(series, tsdb.Series{Metric: d.rules[tenant].Metric, Labels: map[string]string{"test_id": node.TestID, "agent_id": node.AgentID}, Value: 0})
		}
		eval, ok := BuildAlertEvaluator(d.f.pool, fakeQuerier{rows: series}, alert.ChannelDeps{Mail: &dependencyRoutingMail{}}, time.Second, tenancy.ID(tenant), nil, d.f.server.log,
			AlertTagDependencies{Gate: d.f.server.fairnessGate, FlowStore: d.f.server.flowStore, Queries: d.f.server})
		if !ok {
			t.Fatal("shipping evaluator unavailable")
		}
		d.f.server.WithAlertState(tenant, eval.Engine())
		evaluate := func() {
			t.Helper()
			if _, err := eval.Engine().Evaluate(tenancy.WithTenant(t.Context(), tenancy.ID(tenant)), *d.rules[tenant]); err != nil {
				t.Fatal(err)
			}
		}
		evaluate()
		var child alert.ActiveAlert
		for _, active := range eval.Engine().Active() {
			if active.Labels["test_id"] == d.graphs[tenant].Nodes[1].TestID {
				child = active
			}
		}
		if child.Fingerprint == "" {
			t.Fatal("held child disappeared from the active surface")
		}
		read := func(reader string, status int) alertWorkflowResponse {
			t.Helper()
			req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, socket.URL+"/v1/alerts/active/"+url.PathEscape(child.Fingerprint)+"/workflow", nil)
			if err != nil {
				t.Fatal(err)
			}
			token := d.f.tokens[reader]
			if reader == "independent-reader" {
				token = readerToken
			}
			req.Header.Set("Authorization", "Bearer "+token)
			resp, err := socket.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != status {
				t.Fatal("unexpected tenant workflow response", resp.StatusCode, status)
			}
			var out alertWorkflowResponse
			if status == http.StatusOK {
				if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
					t.Fatal(err)
				}
			}
			return out
		}
		out := read(tenant, http.StatusOK)
		if out.Dependency == nil || out.Dependency.State != "held" || len(out.Dependency.Causes) != 1 || out.Dependency.Causes[0].IncidentID != d.cases[tenant] || out.Dependency.EntityID != d.graphs[tenant].Nodes[1].EntityID || out.Dependency.EvidenceID == "" || out.Dependency.ObservationID == "" || out.Dependency.AsOf == nil || out.Dependency.FreshUntil == nil {
			t.Fatal("workflow lost its exact current source and published tenant hold", out.Dependency)
		}
		var stdout, stderr bytes.Buffer
		getenv := func(key string) string {
			return map[string]string{"PROBECTL_API_URL": socket.URL, "PROBECTL_API_TOKEN": d.f.tokens[tenant], "PROBECTL_CA_FILE": ca}[key]
		}
		if code := cli.RunWithStdin([]string{"--json", "alert", "workflow", child.Fingerprint}, getenv, bytes.NewReader(nil), &stdout, &stderr); code != 0 {
			t.Fatal("verified HTTPS workflow CLI read failed", code, stderr.String())
		}
		var nativeCLI alertWorkflowResponse
		if err := json.Unmarshal(stdout.Bytes(), &nativeCLI); err != nil || nativeCLI.Dependency == nil || nativeCLI.Dependency.State != "held" || len(nativeCLI.Dependency.Causes) != 1 || nativeCLI.Dependency.Causes[0].IncidentID != d.cases[tenant] {
			t.Fatal("CLI lost its exact current canonical parent", err, nativeCLI.Dependency)
		}
		read(dependencyOtherTenant(d.f.tenants, tenant), http.StatusNotFound)
		if current := read("independent-reader", http.StatusOK); current.Dependency == nil || current.Dependency.State != "held" {
			t.Fatal("independent reader could not inspect the current owned hold")
		}
		d.f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			_, err := sc.Q.Exec(ctx, `DELETE FROM role_permissions WHERE tenant_id=$1 AND role_id=$2 AND permission_key='incident.read'`, tenant, readerRole)
			return err
		})
		withdrawn := read("independent-reader", http.StatusOK)
		if withdrawn.Dependency == nil || withdrawn.Dependency.State != "withheld" || withdrawn.Dependency.EvidenceID != "" || len(withdrawn.Dependency.Causes) != 0 {
			t.Fatal("policy owner authority concealed the reader's withdrawn permission", withdrawn.Dependency)
		}
		d.f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			return (store.Roles{}).AddPermission(ctx, sc, readerRole, "incident.read")
		})
		d.f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			_, err := sc.Q.Exec(ctx, `DELETE FROM role_permissions WHERE tenant_id=$1 AND role_id=$2 AND permission_key='incident.read'`, tenant, d.f.roles[tenant])
			return err
		})
		out = read("independent-reader", http.StatusOK)
		if out.Dependency == nil || out.Dependency.State != "withheld" || out.Dependency.ContextID != "" || out.Dependency.EvidenceID != "" || len(out.Dependency.Causes) != 0 {
			t.Fatal("workflow disclosed source details after current read withdrawal", out.Dependency)
		}
		d.f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			return (store.Roles{}).AddPermission(ctx, sc, d.f.roles[tenant], "incident.read")
		})
		d.observe(t, tenant, 0, true)
		series[0].Value = 1
		out = read(tenant, http.StatusOK) // the evaluator has not published release yet
		if out.Dependency == nil || out.Dependency.State != "recheck_required" || len(out.Dependency.Causes) != 0 {
			t.Fatal("old marker alone was presented as current hold authority", out.Dependency)
		}
		evaluate()
		out = read(tenant, http.StatusOK)
		if out.Dependency == nil || out.Dependency.State != "ordinary" || len(out.Dependency.Causes) != 0 {
			t.Fatal("published recovery did not clear the served dependency hold", out.Dependency)
		}
	}
	t.Log("real-integration: HTTPS shipping workflow and current PG/RLS authority for paired tenants; source observations and delivery sink modeled")
}

func dependencyWorkflowReader(t *testing.T, d *dependencyRoutingFixture, tenant string) (string, string) {
	t.Helper()
	var userID, roleID string
	d.f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
		user, err := (store.Users{}).Create(ctx, sc, "workflow-reader@"+tenant+".invalid", "Independent workflow reader")
		if err != nil {
			return err
		}
		userID = user.ID
		role, err := (store.Roles{}).Create(ctx, sc, "dependency-workflow-reader", "Workflow reader", "Independent source authority proof")
		if err != nil {
			return err
		}
		roleID = role.ID
		for _, permission := range []string{"alert.read", "topology.read", "entities.read", "test.read", "metrics.read", "incident.read"} {
			if err := (store.Roles{}).AddPermission(ctx, sc, roleID, permission); err != nil {
				return err
			}
		}
		return (store.RoleBindings{}).Bind(ctx, sc, "user", userID, roleID)
	})
	token, err := auth.RandomToken()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.NewMCPTokens(d.f.pool).CreateWithLifetime(t.Context(), tenant, userID, "dependency-workflow-reader", crypto.Hash([]byte(token)), time.Now().Add(time.Hour), nil); err != nil {
		t.Fatal(err)
	}
	return token, roleID
}
