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
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/alert"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/tsdb"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestDependencyDenialReleasesPublicationBeforeDurableAudit(t *testing.T) {
	for _, surface := range []string{"workflow", "native-workflow", "router"} {
		t.Run(surface, func(t *testing.T) {
			d := seedDependencyRoutingFixture(t)
			socket := httptest.NewTLSServer(d.f.server.Handler())
			t.Cleanup(socket.Close)
			counts := map[string]int{}
			for _, tenant := range d.f.tenants {
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
				if _, err := eval.Engine().Evaluate(tenancy.WithTenant(t.Context(), tenancy.ID(tenant)), *d.rules[tenant]); err != nil {
					t.Fatal(err)
				}
				var active alert.ActiveAlert
				for _, item := range eval.Engine().Active() {
					if item.Labels["test_id"] == d.graphs[tenant].Nodes[1].TestID {
						active = item
					}
				}
				if active.Fingerprint == "" {
					t.Fatal("positive source publication did not retain the child")
				}
				d.f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
					_, err := (store.ABACPolicies{}).Create(ctx, sc, auth.Policy{Name: "deny child source after publication lock", Enabled: true, Effect: auth.PolicyDeny,
						Permission: "test.read", Resource: map[string]string{"test_id": active.Labels["test_id"]}, Priority: 100})
					return err
				})
				ctx, cancel := context.WithTimeout(tenancy.WithTenant(t.Context(), tenancy.ID(tenant)), 3*time.Second)
				t.Cleanup(cancel)
				var view *alert.DependencyWorkflow
				switch surface {
				case "workflow":
					req, err := http.NewRequestWithContext(ctx, http.MethodGet, socket.URL+"/v1/alerts/active/"+url.PathEscape(active.Fingerprint)+"/workflow", nil)
					if err != nil {
						t.Fatal(err)
					}
					req.Header.Set("Authorization", "Bearer "+d.f.tokens[tenant])
					resp, err := socket.Client().Do(req)
					if err != nil {
						t.Fatal("ABAC refusal waited on its own publication audit lock", err)
					}
					raw, err := io.ReadAll(resp.Body)
					_ = resp.Body.Close()
					var out alertWorkflowResponse
					if err != nil || resp.StatusCode != http.StatusOK || json.Unmarshal(raw, &out) != nil {
						t.Fatal("ABAC refusal waited on its own publication audit lock", resp.StatusCode, err)
					}
					view = out.Dependency
				case "native-workflow":
					actor, err := NewMCPAuthenticator(d.f.pool, NewTenantStatusCache(d.f.pool, 0), false).Authenticate(ctx, d.f.tokens[tenant])
					if err != nil {
						t.Fatal(err)
					}
					view, err = (mcpTagMutationBackend{server: d.f.server}).AlertDependencyWorkflow(ctx, actor, active.Fingerprint)
					if err != nil {
						t.Fatal("ABAC refusal waited on its own publication audit lock", err)
					}
				case "router":
					attempt := alert.DependencyAttempt{Alert: alert.Alert{TenantID: tenant, RuleID: active.RuleID, Metric: active.Metric, State: alert.StateFiring, Labels: active.Labels, Value: active.Value}, FiringSince: active.Since, RuleUpdatedAt: d.rules[tenant].UpdatedAt}
					out, err := d.f.server.alertDependencyRouter(tenancy.ID(tenant))(ctx, *d.rules[tenant], []alert.DependencyAttempt{attempt})
					if ctx.Err() != nil || err == nil || len(out) != 0 {
						t.Fatal("ABAC refusal waited on its own publication audit lock", err)
					}
				}
				cancel()
				if surface != "router" && (view == nil || view.State != "withheld" || view.ContextID != "" || view.EvidenceID != "" || len(view.Causes) != 0) {
					t.Fatal("denied workflow disclosed source evidence", view)
				}
				counts[tenant]++
				for _, readTenant := range d.f.tenants {
					d.f.in(readTenant, func(ctx context.Context, sc tenancy.Scope) error {
						var count int
						if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE tenant_id=$1 AND action='abac.denied' AND target='test.read'`, readTenant).Scan(&count); err != nil {
							return err
						}
						if count != counts[readTenant] {
							t.Fatal("ABAC refusal lacked an isolated durable audit after publication released", count, counts[readTenant])
						}
						return nil
					})
				}
			}
		})
	}
	t.Log("real-integration: current child-source ABAC refusal and durable tenant audit through HTTPS, native backend and evaluator router; source observations and mail modeled")
}
