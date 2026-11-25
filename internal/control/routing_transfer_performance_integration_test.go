// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package control

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testspec"
)

type routingProbeAPILane struct {
	test   store.RoutingProbeTest
	digest string
	serial string
	egress entity.ICMPEgressWitness
}

// The original probe and packet observations are modeled; the complete
// estimate goes through HTTPS, authorization, the evidence writer and RLS.
func TestRoutingTransferProbeComparisonKeepsTenantsAndHandoffsSeparate(t *testing.T) {
	f, history, ports := newRoutingTransferTestFixture(t)
	var lanes [2][2]routingProbeAPILane
	for i, tenant := range f.tenants {
		owned := ports[tenant]
		lanes[i][0] = configureRoutingPerformanceFixture(t, f, tenant, owned.source, "10.42.0.1", "10.42.0.5")
		lanes[i][1] = configureRoutingPerformanceFixture(t, f, tenant, owned.candidate, "10.43.0.1", "10.43.0.5")
	}
	socket, inputs, _ := seedRoutingTransferTestEstimates(t, f, history, ports, 20*time.Second)
	const endpoint = "/v1/flows/routing-transfer-estimate"
	for i, tenant := range f.tenants {
		from, err := time.Parse(time.RFC3339Nano, inputs[i].ObservedFrom)
		if err != nil {
			t.Fatal(err)
		}
		recordRoutingPerformanceFixture(t, f, tenant, lanes[i][0], from, 200+i*5)
		recordRoutingPerformanceFixture(t, f, tenant, lanes[i][1], from, 50+i*5)
		inputs[i].ProbeComparison = &routingTransferProbeRequest{Source: lanes[i][0].test, Candidate: lanes[i][1].test,
			From: from, To: from.Add(20 * time.Second), Mode: routingImprovePerformance,
			MaximumCandidateP95RTTNanos: "100", MaximumAddedCharge: "2.00"}
	}
	for i, tenant := range f.tenants {
		body := routingTransferPOST(t, socket, f.tokens[tenant], endpoint, inputs[i], http.StatusOK)
		var got routingTransferResponse
		if err := json.Unmarshal(body, &got); err != nil {
			t.Fatal(err)
		}
		upstream := got.Upstream
		if got.Policy == nil || got.Policy.CandidateASN != uint32(64496+i) || upstream == nil ||
			upstream.Status != "measured" || upstream.PairedRounds != 2 || upstream.Recommendation != "move_prefix" ||
			upstream.Source == nil || upstream.Candidate == nil || upstream.Source.TestID != lanes[i][0].test.TestID ||
			upstream.Candidate.TestID != lanes[i][1].test.TestID || upstream.Candidate.P95RTTNanos == nil ||
			*upstream.Candidate.P95RTTNanos != fmt.Sprint(50+i*5) ||
			upstream.P95RTTImprovementNanos != "150" {
			t.Fatalf("the estimate lost the intended upstream and paired performance: %s", body)
		}
		choice := *inputs[i].ProbeComparison
		wrong := inputs[i]
		wrong.ProbeComparison = &choice
		wrong.ProbeComparison.Candidate = lanes[1-i][1].test
		routingTransferPOST(t, socket, f.tokens[tenant], endpoint, wrong, http.StatusNotFound)
		wrong.ProbeComparison.Source, wrong.ProbeComparison.Candidate = lanes[i][1].test, lanes[i][0].test
		routingTransferPOST(t, socket, f.tokens[tenant], endpoint, wrong, http.StatusNotFound)
		wrong.ProbeComparison.Source, wrong.ProbeComparison.Candidate = lanes[i][0].test, lanes[i][1].test
		wrong.ProbeComparison.MaximumCandidateP95RTTNanos = "9"
		body = routingTransferPOST(t, socket, f.tokens[tenant], endpoint, wrong, http.StatusOK)
		got = routingTransferResponse{}
		if err := json.Unmarshal(body, &got); err != nil || got.Policy != nil ||
			got.Upstream == nil || got.Upstream.RecommendationReason != "candidate_exceeds_performance_ceiling" {
			t.Fatalf("a measured but inadmissible candidate reached policy preview: %v %s", err, body)
		}
	}
}

func configureRoutingPerformanceFixture(t *testing.T, f *roleExplanationAPIFixture, tenant string,
	port store.DeviceCounterInterface, peer, source string) routingProbeAPILane {
	t.Helper()
	agentID := pathHealthTestID(t)
	serial := strings.ReplaceAll(pathHealthTestID(t), "-", "")
	if err := store.NewAgentIdentities(f.pool).Record(t.Context(), tenant, agentID, crypto.EntitySPIFFEID(tenant, agentID),
		serial, time.Now().Add(time.Hour), ""); err != nil {
		t.Fatal(err)
	}
	params := map[string]string{
		"count": "2", testspec.RoutingProbeHandoffParam: port.InterfaceID, testspec.RoutingProbePeerParam: peer,
		testspec.RoutingProbeInterfaceParam: "eth0", testspec.RoutingProbeSourceParam: source,
		testspec.RoutingProbePeerMACParam: "02:01:02:03:04:05",
	}
	out := routingProbeAPILane{test: store.RoutingProbeTest{AgentID: agentID}, serial: serial,
		egress: entity.ICMPEgressWitness{Interface: params[testspec.RoutingProbeInterfaceParam], Source: source,
			PeerMAC: params[testspec.RoutingProbePeerMACParam], Transmitted: 2}}
	f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
		for _, permission := range []string{permTestRead, permAgentRead} {
			if err := (store.Roles{}).AddPermission(ctx, sc, f.roles[tenant], permission); err != nil {
				return err
			}
		}
		if _, err := (store.Agents{}).Register(ctx, sc, agentID, "routing probe "+source, source, "fixture",
			crypto.AgentSPIFFEID(tenant, agentID), nil); err != nil {
			return err
		}
		registered, err := (store.Tests{}).Create(ctx, sc, store.TestInput{Name: "routing probe " + source, Type: "icmp",
			Target: "203.0.113.90", IntervalSeconds: 10, TimeoutSeconds: 2, Params: params, Enabled: true})
		if err != nil {
			return err
		}
		out.test.TestID = registered.ID
		out.digest, err = testspec.DefinitionHash(testspec.ExecutableDefinition{ID: registered.ID, Type: registered.Type,
			Target: registered.Target, IntervalSeconds: registered.IntervalSeconds, TimeoutSeconds: registered.TimeoutSeconds, Params: params})
		if err != nil {
			return err
		}
		registry := store.NewEntityRegistry(f.pool)
		if err := registry.AssignPathTestContext(ctx, sc, registered.ID, f.contextID); err != nil {
			return err
		}
		return registry.AssignEntitySource(ctx, sc, entity.SourceKey{Kind: entity.PathAgent, AgentID: agentID, SourceRef: registered.ID},
			f.contextID, f.routerID)
	})
	return out
}

func recordRoutingPerformanceFixture(t *testing.T, f *roleExplanationAPIFixture, tenant string, lane routingProbeAPILane,
	from time.Time, rtt int) {
	t.Helper()
	observations := make([]entity.Observation, 0, 2)
	for round := range 2 {
		start := from.Add(time.Duration(round*10+1) * time.Second)
		end := start.Add(time.Millisecond + 823*time.Nanosecond)
		observations = append(observations, entity.Observation{
			ID: pathHealthTestID(t), ObservedAt: end, SourceRef: "icmp:configured-test",
			Source: entity.SourceKey{Kind: entity.PathAgent, AgentID: lane.test.AgentID, SourceRef: lane.test.TestID},
			Alias:  entity.AliasKey{Kind: entity.AddressAlias, Value: "203.0.113.90"}, ICMP: &entity.ICMPMeasurement{
				Version: entity.ICMPVersionEgress, DefinitionHash: lane.digest, StartedAt: start, CompletedAt: end,
				Requested: 2, Attempted: 2, Transmitted: 2, Replies: 2, ReadComplete: true,
				Responders: []string{"203.0.113.90"}, Egress: &lane.egress,
				RoundTrips: &entity.ICMPRoundTrips{ExecutionNanos: uint64(time.Millisecond), Nanos: []uint64{uint64(rtt), uint64(rtt)}},
			},
		})
	}
	bound := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
	got, err := store.NewEntityRegistry(f.pool).WriteEvidenceBatchReceipt(bound, lane.test.AgentID, lane.serial, observations)
	if err != nil || got.ICMPMeasurements != len(observations) || got.Unresolved != 0 {
		t.Fatalf("routing probe fixture did not retain both originals: %+v %v", got, err)
	}
}
