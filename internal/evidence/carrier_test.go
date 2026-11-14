// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package evidence

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/change"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/incident"
	"github.com/ctlplne/probectl/internal/path"
)

// Modeled original bodies exercise portable signing and privacy selection;
// application-role source reads and physical sender acceptance remain separate.
func TestCarrierPackageKeepsExactOriginalsAndRejectsOfflineTampering(t *testing.T) {
	key, _, err := crypto.GenerateEd25519KeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(key)
	at := time.Date(2026, 11, 1, 12, 0, 0, 123456789, time.UTC)
	from, to := at.Add(-time.Hour), at.Add(time.Hour)
	inc := incident.Incident{ID: "original-incident", Title: "Unrelated customer name", StartedAt: from, LastSeenAt: to, SignalCount: 1,
		Signals: []incident.Signal{{TenantID: "tenant-not-selected", Title: "Unrelated customer signal", Summary: "Customer-private prose"}}}
	carrier := incident.CarrierPack{ContractVersion: incident.CarrierContractVersion, IncidentID: inc.ID, GeneratedAt: to, From: from, To: to,
		Summary: "Original probe observations are available; the carrier fault domain remains unproven.", Interpretation: "Observed differences do not establish causation.",
		Coverage: incident.CarrierCoverage{Measurements: "observed_originals", Traces: "control_plane_only", Routing: "unavailable", Handoffs: "observed_originals", Missing: []string{"independent_agent_traceroutes"}},
		Vantages: []incident.CarrierVantage{}, Routing: []change.Event{}, Handoffs: []incident.CarrierHandoff{{ContextID: "context", RouterID: "router", InterfaceID: "handoff", CurrentRole: "transit", RoleEvaluatedAt: to, Coverage: "observed_originals",
			Counters: []incident.CarrierCounterObservation{{Metric: "probectl.device.if.in.octets", Value: "18446744073709551615", Width: 64, PollStartedAt: at, PollCompletedAt: at.Add(time.Second)}}}}}
	for _, agent := range []string{"[agent-a]", "[agent-b]"} {
		carrier.Vantages = append(carrier.Vantages, incident.CarrierVantage{ContextID: "context", EntityID: "router", TestID: "test-" + agent, AgentID: agent,
			Measurements: change.EffectTestPeriod{From: from, To: to, LossCoverage: "observed_complete_executions", LatencyCoverage: "observed_original_round_trips", Observations: []change.EffectTestObservation{{EvidenceID: "receipt-" + agent, ObservationID: "original-" + agent, ObservedAt: at, Available: true,
				Packets: &change.EffectPackets{Transmitted: "3", Replies: "2", Lost: "1"}, RoundTrips: &change.EffectOriginalRoundTrips{Nanos: []string{"9007199254740993", "9007199254740995"}, ExecutionNanos: "9007199254741000"}}}},
			Traces: []incident.CarrierTrace{{RoundID: "original-control-trace", ObservedAt: at, CompletedAt: &to, TrustedDiscoveryTime: true, Vantage: path.VantageControlPlane, Path: path.Path{Vantage: path.VantageControlPlane}}}})
	}
	var scope string
	for _, tenant := range []string{"selected-tenant-a", "selected-tenant-b"} {
		manifest, attachments, err := Build(BuildInput{TenantID: tenant, Incident: inc, CreatedAt: to, Carrier: &carrier, Conclusion: "Unrelated model answer", Grounded: true})
		if err != nil {
			t.Fatal(err)
		}
		body, err := Sign(manifest, attachments, key)
		if err != nil {
			t.Fatal(err)
		}
		verified, err := Verify(body)
		if err != nil || verified.Profile != "carrier" || len(verified.Evidence) != 1 || verified.Evidence[0].Kind != "incident.carrier" || verified.Evidence[0].State != StateObserved || len(attachments) != 1 {
			t.Fatal("complete portable carrier attachment was unavailable", err)
		}
		if scope == verified.TenantScopeDigest || strings.Contains(string(body), tenant) || strings.Contains(string(body), "Unrelated") || strings.Contains(string(body), "tenant-not-selected") || strings.Contains(string(body), "Customer-private") {
			t.Fatal("carrier profile reused a tenant binding or disclosed nonselected customer data")
		}
		scope = verified.TenantScopeDigest
		var restored incident.CarrierPack
		if json.Unmarshal(attachments[0].Content, &restored) != nil || !reflect.DeepEqual(restored, carrier) || !strings.Contains(string(body), "9007199254740993") || !strings.Contains(string(body), "18446744073709551615") {
			t.Fatal("carrier package rounded, truncated or substituted an original")
		}
		var pkg Package
		if json.Unmarshal(body, &pkg) != nil {
			t.Fatal("invalid signed carrier wire form")
		}
		pkg.Attachments[0].Content = json.RawMessage(`{"summary":"tampered"}`)
		tampered, err := json.Marshal(pkg)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Verify(tampered); err == nil {
			t.Fatal("offline verifier accepted changed carrier evidence")
		}
	}
	if len(inc.Signals) != 1 || inc.Title != "Unrelated customer name" {
		t.Fatal("carrier selection mutated the caller's incident")
	}
	carrier.Vantages, carrier.Handoffs = nil, nil
	manifest, _, err := Build(BuildInput{TenantID: "selected-tenant", Incident: inc, Carrier: &carrier})
	if err != nil || manifest.Evidence[0].State != StateUnknown || manifest.Statements[len(manifest.Statements)-1].Class != "unknown" {
		t.Fatal("empty original coverage became observed carrier evidence", err)
	}
	carrier.Vantages = []incident.CarrierVantage{{ContextID: "context", EntityID: "router", TestID: "test", Measurements: change.EffectTestPeriod{From: from, To: to},
		Traces: []incident.CarrierTrace{{RoundID: "original-control-trace", Vantage: "invented-independent-vantage", Path: path.Path{Vantage: path.VantageControlPlane}}}}}
	if _, _, err := Build(BuildInput{TenantID: "selected-tenant", Incident: inc, Carrier: &carrier}); err == nil {
		t.Fatal("carrier package accepted a substituted trace vantage")
	}
}
