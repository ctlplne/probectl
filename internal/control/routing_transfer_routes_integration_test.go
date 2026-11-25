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

	"github.com/ctlplne/probectl/internal/ai/mcp"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/fairness"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/topology"
)

const (
	routingTransferTestLocal  = "192.0.2.1"
	routingTransferTestRemote = "192.0.2.2"
)

func newRoutingTransferTestFixture(t *testing.T) (*roleExplanationAPIFixture, *flowstore.Memory, map[string]routingTransferPorts) {
	t.Helper()
	f, _, _, _ := newRoleFlowQueryFixture(t)
	history := flowstore.NewMemory()
	f.server.WithFlowStore(history)
	f.server.cfg.FlowQueryLibraryBytes = 64 << 20
	f.server.WithFairness(fairness.NewGate(fairness.DefaultPolicy(), nil))
	graph := topology.NewMemoryStore()
	ports := map[string]routingTransferPorts{}
	generation := pathHealthTestID(t)
	for lane, tenant := range f.tenants {
		seedTopologyFailureLink(t, f, graph, tenant, routingTransferTestLocal, routingTransferTestRemote)
		seedTopologyFailureParallelLinks(t, f, tenant, routingTransferTestLocal, routingTransferTestRemote)
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
	}
	return f, history, ports
}

// Shared device, primary port, route prefix and neighbor generation identities
// deliberately collide. Canonical device ownership and the candidate's ASN must
// still come solely from the authenticated tenant's live routes and interfaces.
func TestRoutingTransferBindsExactRoutesToEachTenantsCurrentOwnedHandoffs(t *testing.T) {
	f, history, ports := newRoutingTransferTestFixture(t)
	actors := map[string]*auth.Principal{}
	for _, tenant := range f.tenants {
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
		assertRoutingTransferSourceDeadlines(t, got, ports[tenant].source)
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
	proveRoutingTransferServedEstimate(t, f, history, ports)
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

func assertRoutingTransferSourceDeadlines(t *testing.T, route routingTransferRoute, port store.DeviceCounterInterface) {
	t.Helper()
	renewed := route
	renewed.validUntil = route.validUntil.Add(time.Second)
	if !route.matchesCurrent(renewed) {
		t.Fatal("a BGP heartbeat invalidated an unchanged route")
	}
	changed := renewed
	changed.candidateView.Generation = "replacement-generation"
	shortened := route
	shortened.validUntil = route.validUntil.Add(-time.Second)
	if route.matchesCurrent(changed) || route.matchesCurrent(shortened) {
		t.Fatal("a new route generation or shortened lease reused the previous route")
	}

	previous := capacityBillPlan{capacityCounterPlan: capacityCounterPlan{tenant: port.Scope.TenantID, members: []capacityBillMemberPlan{{target: port}}}}
	current := previous
	current.members = append([]capacityBillMemberPlan(nil), previous.members...)
	current.members[0].target.ValidUntil = port.ValidUntil.Add(time.Second)
	if !routingTransferBillPlanMatchesCurrent(previous, current) {
		t.Fatal("renewing an owned interface lease invalidated the bill transfer")
	}
	current.members[0].target.ValidUntil = port.ValidUntil.Add(-time.Second)
	if routingTransferBillPlanMatchesCurrent(previous, current) {
		t.Fatal("the bill transfer kept a deadline beyond its current interface authority")
	}
}

// Pair recorded traffic and counter samples under real HTTPS and app-role
// PostgreSQL authority. The physical collector path has its own integration test.
func seedRoutingTransferTestEstimates(t *testing.T, f *roleExplanationAPIFixture, history *flowstore.Memory,
	ports map[string]routingTransferPorts, comparisonSpan ...time.Duration) (*httptest.Server, []routingTransferRequest, []time.Time) {
	t.Helper()
	from := f.observedAt(f.tenants[0]).UTC().Truncate(time.Millisecond).Add(time.Millisecond)
	span := time.Second
	if len(comparisonSpan) > 0 {
		span = comparisonSpan[0]
	}
	to := from.Add(span)
	if wait := time.Until(to); wait > 0 {
		if wait > span+4*time.Second {
			t.Fatal("fixture source clock is outside the allowed skew")
		}
		time.Sleep(wait)
	}
	socket := httptest.NewTLSServer(f.server.Handler())
	t.Cleanup(socket.Close)
	inputs := make([]routingTransferRequest, len(f.tenants))
	exporterDeadlines := make([]time.Time, len(f.tenants))
	for lane, tenant := range f.tenants {
		exporterDeadlines[lane] = time.Now().UTC().Truncate(time.Second).Add(time.Duration(120+lane*30) * time.Second)
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			for _, permission := range []string{permFlowAgreementsRead, permFlowAgreementsWrite} {
				if err := (store.Roles{}).AddPermission(ctx, sc, f.roles[tenant], permission); err != nil {
					return err
				}
			}
			changed, err := sc.Q.Exec(ctx, `UPDATE entity_source_contexts SET expires_at=$4
				WHERE tenant_id=$1 AND context_id=$2 AND source_ref=$3 AND agent_id='role-flow' AND source_kind='flow_exporter'`,
				tenant, f.contextID, routingTransferTestLocal, exporterDeadlines[lane])
			if err == nil && changed.RowsAffected() != 1 {
				t.Fatal("missing the tenant-owned local flow exporter assignment")
			}
			return err
		})
		seedTopologyFailureMeasuredLoad(t, f, history, tenant, routingTransferTestLocal, routingTransferTestRemote, from, to, uint64(lane+1)*1250)
		selected := ports[tenant]
		inputs[lane] = routingTransferRequest{ContextID: f.contextID, Destination: "203.0.113.0/24", LocalPreference: 200,
			routingTransferBillingInput: routingTransferBillingInput{ObservedFrom: from.Format(time.RFC3339Nano), ObservedTo: to.Format(time.RFC3339Nano), MaximumPollGap: (span + 4*time.Second).String(),
				Source:    createRoutingTransferAgreement(t, socket, f.tokens[tenant], selected.source, from, "1000", "4"),
				Candidate: createRoutingTransferAgreement(t, socket, f.tokens[tenant], selected.candidate, from, "0", "1")}}
	}
	return socket, inputs, exporterDeadlines
}

func proveRoutingTransferServedEstimate(t *testing.T, f *roleExplanationAPIFixture, history *flowstore.Memory,
	ports map[string]routingTransferPorts) {
	t.Helper()
	socket, inputs, exporterDeadlines := seedRoutingTransferTestEstimates(t, f, history, ports)
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
			got.Policy.ExactPrefix != got.Prefix || got.Performance != "no_paired_upstream_measurement" || !got.ValidUntil.Equal(exporterDeadlines[lane]) {
			t.Fatalf("the served estimate did not price the owned original traffic and scoped preference: %s", body)
		}
		foreign := inputs[lane]
		foreign.Candidate.AgreementID = inputs[1-lane].Candidate.AgreementID
		routingTransferPOST(t, socket, f.tokens[tenant], "/v1/flows/routing-transfer-estimate", foreign, http.StatusNotFound)
	}
	t.Run("exporter-renewal", func(t *testing.T) {
		proveRoutingTransferExporterRenewal(t, f, inputs, routingTransferTestLocal, exporterDeadlines[0])
	})
	t.Run("native", func(t *testing.T) {
		seedInterfaceRoleMCPConsent(f)
		call := interfaceRoleNativeTLSCaller(t, f, "2026-07-28")
		for lane, tenant := range f.tenants {
			var got routingTransferResponse
			call(tenant, mcp.RoutingTransferToolName, inputs[lane], &got, true)
			if got.Estimate.Candidate == nil || got.Estimate.Candidate.AgreementID != inputs[lane].Candidate.AgreementID ||
				got.Estimate.NetChargeChange != []string{"-26", "-56"}[lane] || got.Policy == nil || got.Policy.CandidateASN != uint32(64496+lane) ||
				!got.ValidUntil.Equal(exporterDeadlines[lane]) {
				t.Fatal("native estimate lost the tenant-owned current handoff or the computed amounts")
			}
			foreign := inputs[lane]
			foreign.Candidate.AgreementID = inputs[1-lane].Candidate.AgreementID
			call(tenant, mcp.RoutingTransferToolName, foreign, nil, false)
		}
	})
}

func proveRoutingTransferExporterRenewal(t *testing.T, f *roleExplanationAPIFixture, inputs []routingTransferRequest, exporter string, deadline time.Time) {
	t.Helper()
	operations := make([]capacityAgreementOperation, len(f.tenants))
	estimates := make([]routingTransferResponse, len(f.tenants))
	for lane, tenant := range f.tenants {
		request := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/v1/flows/routing-transfer-estimate", nil)
		request.Header.Set("Authorization", "Bearer "+f.tokens[tenant])
		actor := f.server.resolvePrincipal(request)
		op, err := f.server.beginCapacityAgreementMode(request.WithContext(auth.WithPrincipal(request.Context(), actor)), false)
		if err != nil {
			t.Fatal(err)
		}
		defer op.done()
		operations[lane] = op
		estimates[lane], err = f.server.runRoutingTransferEstimate(op.request.Context(), op, inputs[lane])
		if err != nil || estimates[lane].Policy == nil {
			t.Fatal("missing estimate before the exporter renewal", err)
		}
	}
	for lane, tenant := range f.tenants {
		refreshRoutingTransferFlowExporter(t, f, tenant, exporter)
		if err := estimates[lane].check(operations[lane].request.Context()); err != nil {
			t.Fatal("renewing a continuous exporter hid the original flow", err)
		}
	}

	setDeadline := func(until time.Time) {
		tenant := f.tenants[0]
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			_, err := sc.Q.Exec(ctx, `UPDATE entity_source_contexts SET expires_at=$4
				WHERE tenant_id=$1 AND context_id=$2 AND agent_id='role-flow' AND source_kind='flow_exporter' AND source_ref=$3`,
				tenant, f.contextID, exporter, until)
			return err
		})
	}
	setDeadline(deadline.Add(-time.Second))
	defer setDeadline(deadline)
	if err := estimates[0].check(operations[0].request.Context()); err == nil || !strings.Contains(err.Error(), "exporter assignments or leases changed") {
		t.Fatal("the estimate survived a shortened exporter lease", err)
	}
	if err := estimates[1].check(operations[1].request.Context()); err != nil {
		t.Fatal("shortening one tenant's exporter lease invalidated the sibling", err)
	}
	setDeadline(deadline)

	tenant := f.tenants[0]
	var assignedAt time.Time
	f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
		return sc.Q.QueryRow(ctx, `SELECT assigned_at FROM entity_source_contexts
			WHERE tenant_id=$1 AND context_id=$2 AND agent_id='role-flow' AND source_kind='flow_exporter' AND source_ref=$3`,
			tenant, f.contextID, exporter).Scan(&assignedAt)
	})
	reassign := func(epoch time.Time) {
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			_, err := sc.Q.Exec(ctx, `UPDATE entity_source_contexts SET assigned_at=$4
				WHERE tenant_id=$1 AND context_id=$2 AND agent_id='role-flow' AND source_kind='flow_exporter' AND source_ref=$3`,
				tenant, f.contextID, exporter, epoch)
			return err
		})
	}
	reassign(f.observedAt(tenant))
	defer reassign(assignedAt)
	refreshRoutingTransferFlowExporter(t, f, tenant, exporter)
	if err := estimates[0].check(operations[0].request.Context()); err == nil || !strings.Contains(err.Error(), "original flow authority or selected prefixes changed") {
		t.Fatal("a new exporter assignment revived the old estimate", err)
	}
	if err := estimates[1].check(operations[1].request.Context()); err != nil {
		t.Fatal("one tenant's exporter reassignment invalidated the sibling", err)
	}
}

func refreshRoutingTransferFlowExporter(t *testing.T, f *roleExplanationAPIFixture, tenant, address string) {
	t.Helper()
	const agent = "role-flow"
	claim := entity.Observation{ID: pathHealthTestID(t), Source: entity.SourceKey{AgentID: agent, Kind: entity.FlowExporter, SourceRef: address},
		Alias:     entity.AliasKey{Kind: entity.FlowExporterAlias, Value: address + "/ipfix/4294967295"},
		SourceRef: "flow:ipfix:domain:4294967295", ObservedAt: f.observedAt(tenant)}
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
	accepted, unresolved, err := writeEntityEvidenceBatchForTest(ctx, store.NewEntityRegistry(f.pool), agent, f.serials[tenant+agent], []entity.Observation{claim})
	if err != nil || accepted != 1 || unresolved != 0 {
		t.Fatal("the current exporter observation was refused", err)
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
