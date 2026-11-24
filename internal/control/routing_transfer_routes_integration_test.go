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
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
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
	"github.com/ctlplne/probectl/internal/topology"
)

// Shared device, primary port, route prefix and neighbor generation identities
// deliberately collide. Canonical device ownership and the candidate's ASN must
// still come solely from the authenticated tenant's live routes and interfaces.
func TestRoutingTransferBindsExactRoutesToEachTenantsCurrentOwnedHandoffs(t *testing.T) {
	f, _, _, _ := newRoleFlowQueryFixture(t)
	history := flowstore.NewMemory()
	f.server.WithFlowStore(history)
	f.server.cfg.FlowQueryLibraryBytes = 64 << 20
	f.server.WithFairness(fairness.NewGate(fairness.DefaultPolicy(), nil))
	graph := topology.NewMemoryStore()
	ports := map[string]routingTransferPorts{}
	actors := map[string]*auth.Principal{}
	const local, remote = "192.0.2.1", "192.0.2.2"
	generation := pathHealthTestID(t)
	for lane, tenant := range f.tenants {
		seedTopologyFailureLink(t, f, graph, tenant, local, remote)
		seedTopologyFailureParallelLinks(t, f, tenant, local, remote)
		seedTopologyFailureNeighborViews(t, f, tenant, generation, uint32(64496+lane))
		scope := entity.Scope{TenantID: tenant, ContextID: f.contextID}
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
		if err := tenancy.InTenantReadSnapshot(ctx, f.pool, func(ctx context.Context, sc tenancy.Scope) error {
			reader := store.NewDeviceCounterCaptures(f.pool)
			first, err := reader.CurrentInterfaceInScope(ctx, sc, scope, f.interfaceID)
			if err != nil {
				return err
			}
			candidate, err := reader.CurrentAddressInterfaceInScope(ctx, sc, scope, f.routerID, "10.43.0.2")
			if err != nil {
				return err
			}
			second, err := reader.CurrentInterfaceInScope(ctx, sc, scope, candidate)
			if err == nil {
				ports[tenant] = routingTransferPorts{source: first, candidate: second}
			}
			return err
		}); err != nil {
			t.Fatal(err)
		}
		request := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/v1/flows/routing-transfer-estimate", nil)
		request.Header.Set("Authorization", "Bearer "+f.tokens[tenant])
		actors[tenant] = f.server.resolvePrincipal(request)
		if actors[tenant] == nil || actors[tenant].TenantID != tenant {
			t.Fatal("fixture lost the exact tenant credential")
		}
	}
	check := func(lane int) {
		t.Helper()
		tenant := f.tenants[lane]
		scope := entity.Scope{TenantID: tenant, ContextID: f.contextID}
		prefix := netip.MustParsePrefix("203.0.113.0/24")
		budget := flowstore.DefaultExplorerBudget()
		got, err := f.server.authorizeRoutingTransferRoute(t.Context(), actors[tenant], scope, ports[tenant], prefix, budget)
		if err != nil || got.prefix != prefix || got.selected.String() != "10.42.0.1" || got.candidate.String() != "10.43.0.1" ||
			got.candidateASN != uint32(64496+lane) || got.selectedView.Generation == "" || got.candidateView.Generation == "" {
			t.Fatalf("owned routing transfer lost the exact recorded next hop or leaked the sibling's ASN: %+v %v", got, err)
		}
		other := ports[f.tenants[1-lane]]
		if got, err := f.server.authorizeRoutingTransferRoute(t.Context(), actors[tenant], scope, other, prefix, budget); err == nil || got.candidate.IsValid() {
			t.Fatal("the caller received an eligible route from foreign physical handoffs")
		}
	}
	check(0)
	check(1)
	first := f.tenants[0]
	f.in(first, func(ctx context.Context, sc tenancy.Scope) error {
		return (store.Roles{}).AddPermission(ctx, sc, f.roles[first], permFlowAgreementsRead)
	})
	for lane, tenant := range f.tenants {
		r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/v1/flows/routing-transfer-estimate", strings.NewReader(`{}`))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Authorization", "Bearer "+f.tokens[tenant])
		response := httptest.NewRecorder()
		f.server.Handler().ServeHTTP(response, r)
		if response.Code != []int{http.StatusUnprocessableEntity, http.StatusForbidden}[lane] {
			t.Fatalf("the registered route missed its independent financial permission or input validation: %d", response.Code)
		}
	}
	proveRoutingTransferServedEstimate(t, f, history, ports, local, remote)
	f.in(first, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `DELETE FROM role_permissions WHERE tenant_id=$1 AND role_id=$2 AND permission_key='events.read'`, first, f.roles[first])
		return err
	})
	refreshed := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/v1/flows/routing-transfer-estimate", nil)
	refreshed.Header.Set("Authorization", "Bearer "+f.tokens[first])
	actors[first] = f.server.resolvePrincipal(refreshed)
	if got, err := f.server.authorizeRoutingTransferRoute(t.Context(), actors[first], entity.Scope{TenantID: first, ContextID: f.contextID},
		ports[first], netip.MustParsePrefix("203.0.113.0/24"), flowstore.DefaultExplorerBudget()); err == nil || got.candidate.IsValid() {
		t.Fatal("the previous credential kept access after its owning tenant revoked route evidence permission")
	}
	check(1)
}

// The HTTPS handler and app-role PostgreSQL authority path are real. The
// traffic and counter samples are recorded fixture inputs on the normal store
// interfaces. No elapsed physical lab history is claimed here.
func proveRoutingTransferServedEstimate(t *testing.T, f *roleExplanationAPIFixture, history *flowstore.Memory,
	ports map[string]routingTransferPorts, local, remote string) {
	t.Helper()
	from := f.observedAt(f.tenants[0]).UTC().Truncate(time.Millisecond).Add(time.Millisecond)
	to := from.Add(time.Second)
	if wait := time.Until(to); wait > 0 {
		if wait > 5*time.Second {
			t.Fatal("fixture source clock is outside the allowed skew")
		}
		time.Sleep(wait)
	}
	socket := httptest.NewTLSServer(f.server.Handler())
	t.Cleanup(socket.Close)
	inputs := make([]routingTransferRequest, len(f.tenants))
	for lane, tenant := range f.tenants {
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			for _, permission := range []string{permFlowAgreementsRead, permFlowAgreementsWrite} {
				if err := (store.Roles{}).AddPermission(ctx, sc, f.roles[tenant], permission); err != nil {
					return err
				}
			}
			return nil
		})
		seedTopologyFailureMeasuredLoad(t, f, history, tenant, local, remote, from, to, uint64(lane+1)*1250)
		selected := ports[tenant]
		inputs[lane] = routingTransferRequest{ContextID: f.contextID, Destination: "203.0.113.0/24", LocalPreference: 200,
			routingTransferBillingInput: routingTransferBillingInput{ObservedFrom: from.Format(time.RFC3339Nano), ObservedTo: to.Format(time.RFC3339Nano), MaximumPollGap: "5s",
				Source:    createRoutingTransferAgreement(t, socket, f.tokens[tenant], selected.source, from, "1000", "4"),
				Candidate: createRoutingTransferAgreement(t, socket, f.tokens[tenant], selected.candidate, from, "0", "1")}}
	}
	for lane, tenant := range f.tenants {
		body := routingTransferPOST(t, socket, f.tokens[tenant], "/v1/flows/routing-transfer-estimate", inputs[lane], http.StatusOK)
		var got routingTransferResponse
		if err := json.Unmarshal(body, &got); err != nil {
			t.Fatal(err)
		}
		wantRate := fmt.Sprint(10000*(lane+1) + 2000)
		if got.EstimateBasis != "observed_window_at_recorded_unit_rates" || got.Prefix != inputs[lane].Destination ||
			got.Estimate.Status != "estimated" || got.Estimate.NetChargeChange != []string{"-26", "-56"}[lane] ||
			got.Estimate.Candidate == nil || got.Estimate.Candidate.AfterP95.BPSNumerator != wantRate || got.Estimate.Candidate.AfterP95.BPSDenominator != "1" ||
			got.Policy == nil || got.Policy.CandidateASN != uint32(64496+lane) || got.Policy.CandidatePeer != "10.43.0.1" || got.Policy.LocalPreference != 200 ||
			got.Policy.ExactPrefix != got.Prefix || got.Performance != "no_paired_upstream_measurement" {
			t.Fatalf("the served estimate did not price the owned original traffic and scoped preference: %s", body)
		}
		foreign := inputs[lane]
		foreign.Candidate.AgreementID = inputs[1-lane].Candidate.AgreementID
		routingTransferPOST(t, socket, f.tokens[tenant], "/v1/flows/routing-transfer-estimate", foreign, http.StatusNotFound)
	}
}

func createRoutingTransferAgreement(t *testing.T, socket *httptest.Server, token string, port store.DeviceCounterInterface, from time.Time,
	commit, price string) routingTransferBillingSelection {
	t.Helper()
	definition := flow.CapacityAgreementDefinition{Name: "Owned handoff terms", ValidFrom: from.Add(-time.Hour).Format(time.RFC3339Nano),
		Target:     flow.CapacityTarget{Kind: "interface", ContextID: port.Scope.ContextID, InterfaceID: port.InterfaceID},
		BillingDay: 1, Timezone: "UTC", Direction: "out", Currency: "USD", CommitBPS: commit, UnitBPS: "1000", UnitPrice: price}
	encoded := routingTransferPOST(t, socket, token, "/v1/flows/capacity/agreements", flow.SaveCapacityAgreement{Definition: definition}, http.StatusCreated)
	var created flow.CapacityAgreement
	if err := json.Unmarshal(encoded, &created); err != nil || created.ID == "" || created.Version == "" {
		t.Fatalf("failed to record separate owned handoff terms: %s %v", encoded, err)
	}
	return routingTransferBillingSelection{AgreementID: created.ID, Version: created.Version, EgressID: port.InterfaceID,
		Bounds: []flow.CapacityPhysicalBound{{ContextID: port.Scope.ContextID, InterfaceID: port.InterfaceID, MaxBPS: "1000000"}}}
}

func routingTransferPOST(t *testing.T, socket *httptest.Server, token, path string, body any, status int) []byte {
	t.Helper()
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, socket.URL+path, bytes.NewReader(encoded))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	res, err := socket.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	actual, err := io.ReadAll(res.Body)
	if err != nil || res.StatusCode != status {
		t.Fatalf("%s returned %d, want %d: %s %v", path, res.StatusCode, status, actual, err)
	}
	return actual
}
