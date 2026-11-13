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
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	googleuuid "github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/fairness"
	"github.com/ctlplne/probectl/internal/incident"
	"github.com/ctlplne/probectl/internal/slo"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestIncidentImpactServesOriginalTestComparisonsAndCurrentTenantPermission(t *testing.T) {
	d := seedDependencyRoutingFixture(t)
	f := d.f
	f.server.WithFlowStore(flowstore.NewMemory()).WithFairness(fairness.NewGate(fairness.DefaultPolicy(), nil))
	ids := map[string]string{}
	definitions := []slo.SLO{}
	tagIDs := map[string]string{}
	for lane, tenant := range f.tenants {
		d.observe(t, tenant, 0, lane == 1)
		ids[tenant] = googleuuid.NewString()
		tagIDs[tenant] = googleuuid.NewString()
		definitions = append(definitions, slo.SLO{TenantID: tenant, Name: "owned-objective-" + tenant, Service: "checkout", CanaryType: "icmp", TestID: d.graphs[tenant].Nodes[0].TestID, Objective: 0.999, Window: 24 * time.Hour})
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			for _, permission := range []string{permIncidentRead, permFlowRead, permTagsRead} {
				if err := (store.Roles{}).AddPermission(ctx, sc, f.roles[tenant], permission); err != nil {
					return err
				}
			}
			if _, err := sc.Q.Exec(ctx, `DELETE FROM role_permissions WHERE tenant_id=$1 AND role_id=$2 AND permission_key=$3`, tenant, f.roles[tenant], permTestRead); err != nil {
				return err
			}
			if _, err := sc.Q.Exec(ctx, `INSERT INTO tenant_tag_definitions(tenant_id,id,key) VALUES($1,$2,'customer')`, tenant, tagIDs[tenant]); err != nil {
				return err
			}
			if _, err := sc.Q.Exec(ctx, `INSERT INTO tenant_tag_assignments(tenant_id,context_id,id,tag_id,target_kind,test_id,value,source) VALUES($1,$2,$3,$4,'test',$5,$6,'manual')`, tenant, f.contextID, googleuuid.NewString(), tagIDs[tenant], d.graphs[tenant].Nodes[0].TestID, "customer-"+tenant); err != nil {
				return err
			}
			_, err := sc.Q.Exec(ctx, `INSERT INTO incidents(tenant_id,id,title,entity_context_id,entity_id,identity_lookup_attempted) VALUES($1,$2,'test comparison',$3,$4,true)`, tenant, ids[tenant], f.contextID, d.graphs[tenant].Nodes[0].EntityID)
			return err
		})
	}
	f.server.WithSLO(slo.NewEngine(definitions))
	socket := httptest.NewTLSServer(f.server.Handler())
	t.Cleanup(socket.Close)
	request := func(tenant, id string, tests bool) (int, incident.ImpactResponse) {
		t.Helper()
		body, err := json.Marshal(incident.ImpactInput{From: time.Now().UTC().Add(-time.Minute), To: time.Now().UTC(), IncludeTests: tests, CustomerTagKey: "customer"})
		if err != nil {
			t.Fatal(err)
		}
		req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, socket.URL+"/v1/incidents/"+id+"/impact", bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+f.tokens[tenant])
		req.Header.Set("Content-Type", "application/json")
		response, err := socket.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		raw, err := io.ReadAll(response.Body)
		if err != nil {
			t.Fatal(err)
		}
		var result incident.ImpactResponse
		if response.StatusCode == http.StatusOK {
			if err := json.Unmarshal(raw, &result); err != nil {
				t.Fatal(err)
			}
		}
		return response.StatusCode, result
	}
	for lane, tenant := range f.tenants {
		if status, _ := request(tenant, ids[tenant], true); status != http.StatusForbidden {
			t.Fatal("incident permission implicitly disclosed tests", status)
		}
		if status, result := request(tenant, ids[tenant], false); status != http.StatusOK || result.TestCoverage != "not_evaluated" || len(result.Tests) != 0 {
			t.Fatal("traffic-only caller acquired test authority or lost existing behavior", status, result)
		}
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			return (store.Roles{}).AddPermission(ctx, sc, f.roles[tenant], permTestRead)
		})
		status, result := request(tenant, ids[tenant], true)
		if status != http.StatusOK || len(result.Tests) != 1 || result.Tests[0].TestID != d.graphs[tenant].Nodes[0].TestID || result.ValidUntil == nil {
			t.Fatal("served comparison lost owned complete original history or expiry", status, result)
		}
		current, previous := result.Tests[0].Current, result.Tests[0].Previous
		if current.Successful != lane || current.Failed != 2-lane || current.Unknown != 0 || len(current.Observations) != 2 || len(previous.Observations) != 0 || previous.Packets != nil || previous.Coverage != "no_retained_observations" {
			t.Fatal("sibling outcomes, missing baseline or local IO became measured health", current, previous)
		}
		if len(result.SLOs) != 1 || result.SLOs[0].Name != "owned-objective-"+tenant || result.SLOs[0].Current.FailedInputs != 2-lane || result.SLOs[0].Previous.FailedInputs != 0 || result.SLOs[0].ObjectiveRatio != "0.999" {
			t.Fatal("SLO input evidence borrowed another tenant or invented rolling-budget state", result.SLOs)
		}
		failed := map[string]bool{}
		for _, original := range current.Observations {
			if original.Status == "failed" {
				failed[original.EvidenceID] = true
			}
		}
		for _, source := range result.SLOs[0].Current.Sources {
			if source.ContextID != f.contextID || source.TestID != d.graphs[tenant].Nodes[0].TestID {
				t.Fatal("SLO citation changed its exact source", source)
			}
			for _, id := range source.EvidenceIDs {
				if !failed[id] {
					t.Fatal("SLO citation named an unavailable or successful observation", id)
				}
				delete(failed, id)
			}
		}
		if len(failed) != 0 {
			t.Fatal("SLO citations omitted an original failed input", failed)
		}
		if len(result.Customers) != 1 || result.Customers[0].Value != "customer-"+tenant || result.Customers[0].Current != nil || result.Customers[0].Previous != nil || len(result.Customers[0].TestIDs) != 1 || len(result.Customers[0].SLOIDs) != 1 || result.Customers[0].SLOIDs[0] != "owned-objective-"+tenant || len(result.Customers[0].TagIDs) != 1 || result.Customers[0].TagIDs[0] != tagIDs[tenant] || len(result.Customers[0].EvidenceIDs) != 2-lane || result.CustomerCoverage != "observed_flows_and_original_test_inputs" {
			t.Fatal("served customer attribution invented traffic or borrowed another tenant's test/SLO tags", result.Customers, result.CustomerCoverage)
		}
		if status, _ := request(tenant, ids[f.tenants[1-lane]], true); status == http.StatusOK {
			t.Fatal("served comparison disclosed the sibling incident", status)
		}
	}
	a, b := f.tenants[0], f.tenants[1]
	var tagDeniedID string
	f.in(a, func(ctx context.Context, sc tenancy.Scope) error {
		policy, err := (store.ABACPolicies{}).Create(ctx, sc, auth.Policy{Name: "deny selected test customer", Enabled: true, Effect: auth.PolicyDeny, Permission: permTagsRead, Resource: map[string]string{"test_id": d.graphs[a].Nodes[0].TestID}, Priority: 100})
		if err == nil {
			tagDeniedID = policy.ID
		}
		return err
	})
	if status, result := request(a, ids[a], true); status != http.StatusForbidden || len(result.Customers) != 0 {
		t.Fatal("per-test tag denial returned an allowed customer prefix", status, result)
	}
	if status, result := request(b, ids[b], true); status != http.StatusOK || len(result.Customers) != 1 {
		t.Fatal("tag denial changed sibling customer attribution", status, result)
	}
	f.in(a, func(ctx context.Context, sc tenancy.Scope) error {
		return (store.ABACPolicies{}).Delete(ctx, sc, tagDeniedID)
	})
	var deniedID string
	f.in(a, func(ctx context.Context, sc tenancy.Scope) error {
		policy, err := (store.ABACPolicies{}).Create(ctx, sc, auth.Policy{Name: "deny selected test", Enabled: true, Effect: auth.PolicyDeny, Permission: permTestRead, Resource: map[string]string{"test_id": d.graphs[a].Nodes[0].TestID}, Priority: 100})
		if err == nil {
			deniedID = policy.ID
		}
		return err
	})
	if status, result := request(a, ids[a], true); status != http.StatusForbidden || len(result.Tests) != 0 {
		t.Fatal("per-test ABAC denial returned an allowed population prefix", status, result)
	}
	f.in(a, func(ctx context.Context, sc tenancy.Scope) error {
		return (store.ABACPolicies{}).Delete(ctx, sc, deniedID)
	})
	f.in(a, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `DELETE FROM role_permissions WHERE tenant_id=$1 AND role_id=$2 AND permission_key=$3`, a, f.roles[a], permTestRead)
		return err
	})
	if status, _ := request(a, ids[a], true); status != http.StatusForbidden {
		t.Fatal("stale credential retained withdrawn current test permission", status)
	}
	if status, result := request(b, ids[b], true); status != http.StatusOK || len(result.Tests) != 1 {
		t.Fatal("permission withdrawal changed sibling test evidence", status, result)
	}
	t.Log("real-integration: served HTTPS/current-user/paired app-role PG-RLS comparisons and permission withdrawal; probe rows are modeled, physical G4a and SLO/customer attribution remain owed")
}
