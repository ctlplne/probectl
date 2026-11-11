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
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/fairness"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/pkg/sdk"
)

// Actual app-role Postgres/FORCE-RLS, current bearer auth and verified HTTPS.
// Flow storage is empty memory and public data/issued identities are seeded;
// this proves current served authority and honest absence, not traffic math,
// actual ClickHouse, physical senders or a complete native wire journey.
func TestPeeringEstimateAPIKeepsCurrentTenantSourcesAndUnprovenEmptyIntervals(t *testing.T) {
	f, actors, input := newPeeringEstimateAPIFixture(t)

	socket := httptest.NewTLSServer(f.server.Handler())
	t.Cleanup(socket.Close)
	read := func(tenant string) (int, flow.PeeringEstimateResponse) {
		t.Helper()
		body, err := json.Marshal(input)
		if err != nil {
			t.Fatal(err)
		}
		r, err := http.NewRequestWithContext(t.Context(), http.MethodPost, socket.URL+"/v1/flows/peering-estimate", strings.NewReader(string(body)))
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set("Authorization", "Bearer "+f.tokens[tenant])
		r.Header.Set("Content-Type", "application/json")
		response, err := socket.Client().Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		raw, err := io.ReadAll(response.Body)
		if err != nil {
			t.Fatal(err)
		}
		var out flow.PeeringEstimateResponse
		if response.StatusCode == http.StatusOK && json.Unmarshal(raw, &out) != nil {
			t.Fatal("invalid served peering response")
		}
		if response.StatusCode != http.StatusOK {
			t.Log("served peering status", response.StatusCode, string(raw))
		}
		return response.StatusCode, out
	}
	assertEmpty := func(tenant string) {
		t.Helper()
		status, out := read(tenant)
		if status != http.StatusOK || !out.Preview || !out.Target.Eligible || out.Target.ContextID != f.contextID || out.Target.InterfaceID != f.interfaceID || len(out.Target.MemberIDs) != 5001 || out.P95 != nil || out.Coverage.CompleteObservedInputs || out.Coverage.ExpectedIntervals != 12 || out.Reason != "missing_observed_intervals" {
			t.Fatal("actual served peering invented an empty-interval p95 or lost complete owned target evidence", status, out)
		}
	}
	a, b := f.tenants[0], f.tenants[1]
	assertEmpty(a)
	assertEmpty(b)
	client := sdk.NewClient(socket.URL, sdk.WithHTTPClient(socket.Client()), sdk.WithToken(f.tokens[a]))
	body, _ := json.Marshal(input)
	var typed sdk.PeeringEstimateInput
	if err := json.Unmarshal(body, &typed); err != nil {
		t.Fatal(err)
	}
	if out, err := client.EstimateFlowPeering(t.Context(), sdk.EstimateFlowPeeringRequest{Body: &typed}); err != nil || out.Reason != "missing_observed_intervals" || len(out.Target.MembershipSources) != 5001 || out.KnownEligibleP95.BitsPerSecondNumerator != "" {
		t.Fatal("actual generated SDK lost current authority or honest absence", err)
	}
	if raw, err := (mcpPeeringBackend{f.server}).PeeringEstimate(t.Context(), actors[a], input); err != nil || len(raw) == 0 {
		t.Fatal("native peering adapter lost current served authority", err)
	}
	f.in(a, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `DELETE FROM role_permissions WHERE tenant_id=$1 AND role_id=$2 AND permission_key='events.read'`, a, f.roles[a])
		return err
	})
	if status, _ := read(a); status != http.StatusForbidden {
		t.Fatal("actual peering estimate bypassed current source-plane permission", status)
	}
	if raw, err := (mcpPeeringBackend{f.server}).PeeringEstimate(t.Context(), actors[a], input); err == nil || len(raw) != 0 {
		t.Fatal("stale native peering principal retained source authority", err)
	}
	assertEmpty(b)
	f.in(a, func(ctx context.Context, sc tenancy.Scope) error {
		return (store.Roles{}).AddPermission(ctx, sc, f.roles[a], "events.read")
	})
	f.in(a, func(ctx context.Context, sc tenancy.Scope) error {
		result, err := sc.Q.Exec(ctx, `DELETE FROM entity_source_contexts WHERE tenant_id=$1 AND agent_id='role-flow' AND source_kind='flow_exporter'`, a)
		if err == nil && result.RowsAffected() != 1 {
			t.Fatal("peering source withdrawal did not remove its exact fixture assignment")
		}
		return err
	})
	if status, _ := read(a); status == http.StatusOK {
		t.Fatal("actual peering estimate reused withdrawn exporter ownership", status)
	}
	assertEmpty(b)
}

func newPeeringEstimateAPIFixture(t *testing.T) (*roleExplanationAPIFixture, map[string]*auth.Principal, flow.PeeringEstimateInput) {
	t.Helper()
	f, _, actors, at := newRoleFlowQueryFixture(t)
	f.server.WithFlowStore(flowstore.NewMemory())
	policy := fairness.DefaultPolicy()
	policy.QueryConcurrency = 2
	policy.QueriesPerMin = 60
	f.server.WithFairness(fairness.NewGate(policy, nil))
	f.server.openDataEnricher = peeringTargetSources(t, time.Now().UTC(), 11, 5001, "10.42.0.0/24")
	for _, tenant := range f.tenants {
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			configuration := store.InterfaceRoleConfiguration{}
			previous, err := configuration.Policy(ctx, sc, f.contextID, roleExplanationStoreBudget())
			if err != nil {
				return err
			}
			if _, err := configuration.PutPolicy(ctx, sc, f.contextID, previous.ID, previous.Revision, entity.InterfaceRolePolicyDefinition{}, roleExplanationStoreBudget()); err != nil {
				return err
			}
			if tenant == f.tenants[1] {
				override, err := configuration.Override(ctx, sc, f.contextID, f.interfaceID)
				if err != nil {
					return err
				}
				_, err = configuration.PutOverride(ctx, sc, f.contextID, f.interfaceID, override.ID, override.Revision, entity.InterfaceRoleIX)
				return err
			}
			return nil
		})
	}
	input := flow.PeeringEstimateInput{ContextID: f.contextID, InterfaceID: f.interfaceID, PeerASN: ^uint32(0), IXID: "71", LANID: "11", Direction: "inbound", From: at.Add(-time.Hour), To: at, BucketSeconds: 300}
	return f, actors, input
}
