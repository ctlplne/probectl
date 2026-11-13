// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"encoding/hex"
	"encoding/json"
	"math"
	"net/netip"
	"strings"
	"testing"
	"time"

	gouuid "github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/ai"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/incident"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tags"
)

func TestIncidentImpactExactObservedCountersAndCustomerUnion(t *testing.T) {
	at := time.Now().UTC().Add(-time.Minute)
	contextID, router := gouuid.NewString(), gouuid.NewString()
	for _, tenant := range []string{gouuid.NewString(), gouuid.NewString()} {
		var key [32]byte
		key[0] = 1
		row := flowstore.Row{TenantID: tenant, AgentID: "owned-flow", Exporter: "192.0.2.1", Protocol: "ipfix", ObsDomain: math.MaxUint32,
			TS: at, StartTS: at.Add(-time.Second), SrcAddr: "203.0.113.1", DstAddr: "198.51.100.2", Bytes: math.MaxUint64, Packets: 7, Sampling: 3,
			RoutingCaptureKey: hex.EncodeToString(key[:]), RoutingCapturedUnixNanos: at.UnixNano()}
		owner := store.CapturedFlowOwner{Available: true, Reference: entity.FlowCaptureReference{Key: key, CapturedAt: at},
			Owner: store.InterfaceRoleFlowBinding{Scope: entity.Scope{TenantID: tenant, ContextID: contextID}, AgentID: row.AgentID, RouterID: router, SourceID: "evidence/original", Exporter: netip.MustParseAddr(row.Exporter), Protocol: row.Protocol, Domain: row.ObsDomain}, CurrentSourceID: "evidence/current"}
		owners := map[string]store.CapturedFlowOwner{row.RoutingCaptureKey: owner}
		period := incident.ImpactPeriod{From: at.Add(-time.Second), To: at.Add(time.Second), Captures: []incident.ImpactCaptureCitation{}}
		out, err := summarizeIncidentTraffic(t.Context(), tenant, period, []flowstore.Row{row, row}, owners, 1<<20)
		if err != nil || out.AttestedRecords != 1 || len(out.Captures) != 1 || out.ObservedTotals == nil || out.ObservedTotals.RawBytes != "18446744073709551615" || out.ObservedTotals.ScaledBytes != "55340232221128654845" || out.ObservedTotals.ScaledPackets != "21" {
			t.Fatal("exact observation was overflowed, rounded or multiplied", out, err)
		}
		prefixIDs := []string{gouuid.NewString(), gouuid.NewString()}
		var prefixes []tags.PrefixProjection
		for i, network := range []string{"203.0.113.0/24", "198.51.100.0/24"} {
			prefixes = append(prefixes, tags.PrefixProjection{Scope: tags.Scope{TenantID: tenant, ContextID: contextID}, ID: prefixIDs[i], Network: netip.MustParsePrefix(network), Values: map[string]string{"customer": "owned-" + tenant}})
		}
		data, err := flowstore.NewTagQueryData(tenant, 1, []tags.Definition{{TenantID: tenant, ID: gouuid.NewString(), Key: "customer"}}, []tags.ExporterProjection{{Exporter: row.Exporter, ContextID: contextID}}, 1<<20, flowstore.TagQuerySources{Context: t.Context(), Prefixes: prefixes})
		if err != nil {
			t.Fatal(err)
		}
		customers, unknown, err := summarizeIncidentCustomers(t.Context(), tenant, "customer", [2][]flowstore.Row{{row, row}, {}}, owners, data, 1<<20)
		if err != nil || unknown != 0 || len(customers) != 1 || customers[0].Value != "owned-"+tenant || len(customers[0].PrefixIDs) != 2 || len(customers[0].CaptureKeys) != 1 || customers[0].Current.ScaledBytes != "55340232221128654845" || customers[0].Previous != nil {
			t.Fatal("customer union multiplied traffic, borrowed another tenant or fabricated baseline zero", customers, unknown, err)
		}
		legacy := row
		legacy.RoutingCaptureKey = ""
		legacy.RoutingCapturedUnixNanos = 0
		missing, err := summarizeIncidentTraffic(t.Context(), tenant, period, []flowstore.Row{legacy}, owners, 1<<20)
		if err != nil || missing.UnverifiedRecords != 1 || missing.ObservedTotals != nil || missing.Coverage != "unavailable_original_capture" {
			t.Fatal("missing original coverage was rendered as healthy zero", missing, err)
		}
		foreign := row
		foreign.TenantID = gouuid.NewString()
		if _, err := summarizeIncidentTraffic(t.Context(), tenant, period, []flowstore.Row{foreign}, owners, 1<<20); err == nil {
			t.Fatal("foreign raw row crossed the impact boundary")
		}
		owner.Owner.TenantID = foreign.TenantID
		owners[row.RoutingCaptureKey] = owner
		if customers, _, err := summarizeIncidentCustomers(t.Context(), tenant, "customer", [2][]flowstore.Row{{row}, {}}, owners, data, 1<<20); err != nil || len(customers) != 0 {
			t.Fatal("foreign capture owner supplied customer membership", customers, err)
		}
	}
}

func TestNativeIncidentImpactPreservesComputedSignedCounters(t *testing.T) {
	value := incident.ImpactResponse{ContractVersion: "probectl.incident-impact.v1", IncidentID: gouuid.NewString(), ObservedByteChange: "-55340232221128654845", Members: []incident.ImpactMember{}, Customers: []incident.ImpactCustomer{}, UnresolvedSignalIDs: []string{}}
	body, err := marshalNativeIncidentImpact(value)
	if err != nil {
		t.Fatal(err)
	}
	var parsed map[string]json.RawMessage
	if err := json.Unmarshal(body, &parsed); err != nil {
		t.Fatal(err)
	}
	var count string
	if err := json.Unmarshal(parsed["observed_scaled_byte_change"], &count); err != nil || count != value.ObservedByteChange {
		t.Fatal("native response narrowed the exact signed weekly change", count, err)
	}
}

func TestNativeIncidentImpactPreservesStoredCitationsAndRedactsLabels(t *testing.T) {
	const id = "40000000-0000-4004-8000-abcdefabcdef"
	const digest = "4111111111111111aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	source := "evidence/" + id
	capture := incident.ImpactCaptureCitation{Key: digest, ContextID: id, RouterID: id, OriginalSourceID: source, CurrentSourceID: source}
	value := incident.ImpactResponse{ContractVersion: "probectl.incident-impact.v1", IncidentID: id,
		Current:   incident.ImpactPeriod{Captures: []incident.ImpactCaptureCitation{capture}},
		Previous:  incident.ImpactPeriod{Captures: []incident.ImpactCaptureCitation{}},
		Members:   []incident.ImpactMember{{ContextID: id, EntityID: id, SignalIDs: []string{id}, SourceIDs: []string{source}}},
		Customers: []incident.ImpactCustomer{{ContextID: id, PrefixIDs: []string{id}, TestIDs: []string{}, SLOIDs: []string{}, CaptureKeys: []string{digest}, Value: "password=private-fixture 192.0.2.1 card=4111-1111-1111-1111 " + id}},
	}
	body, err := marshalNativeIncidentImpact(value)
	if err != nil {
		t.Fatal(err)
	}
	redacted := ai.RedactTextForTenant(string(body), ai.DefaultRedaction, id)
	var got incident.ImpactResponse
	if err := json.Unmarshal([]byte(redacted), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Current.Captures) != 1 || got.Current.Captures[0].Key != digest || got.Current.Captures[0].OriginalSourceID != source || got.Current.Captures[0].CurrentSourceID != source || len(got.Members) != 1 || len(got.Members[0].SourceIDs) != 1 || got.Members[0].SourceIDs[0] != source || len(got.Customers) != 1 || len(got.Customers[0].CaptureKeys) != 1 || got.Customers[0].CaptureKeys[0] != digest {
		t.Fatal("native impact redaction changed a stored canonical citation", got.Current.Captures, got.Members, got.Customers)
	}
	if strings.Contains(redacted, "private-fixture") || strings.Contains(redacted, "192.0.2.1") || strings.Contains(redacted, "4111-1111-1111-1111") || got.Customers[0].Value == value.Customers[0].Value || !strings.Contains(redacted, "[secret:") || !strings.Contains(redacted, "[pan:") {
		t.Fatal("native citation encoding exempted operator-owned labels from redaction")
	}
}

func TestNativeIncidentImpactRejectsUntrustedCitationShapes(t *testing.T) {
	for _, source := range []string{"", "collector/40000000-0000-4004-8000-abcdefabcdef", "evidence/password=private", "evidence/40000000-0000-4004-8000-ABCDEFABCDEF", "evidence/40000000-0000-4004-8000-abcdefabcdef/label"} {
		value := incident.ImpactResponse{ContractVersion: "probectl.incident-impact.v1", IncidentID: gouuid.NewString(), Members: []incident.ImpactMember{{SourceIDs: []string{source}}}}
		if body, err := marshalNativeIncidentImpact(value); err == nil || body != nil {
			t.Fatal("untrusted source acquired canonical metadata encoding", source, err)
		}
	}
}

func TestNativeIncidentImpactPreservesContractVersionAndRedactsProse(t *testing.T) {
	value := incident.ImpactResponse{ContractVersion: "probectl.incident-impact.v1", IncidentID: gouuid.NewString(), Customers: []incident.ImpactCustomer{{ContextID: gouuid.NewString(), Value: "host.example password=private-fixture 192.0.2.1"}}}
	body, err := marshalNativeIncidentImpact(value)
	if err != nil {
		t.Fatal(err)
	}
	redacted := ai.RedactTextForTenant(string(body), ai.DefaultRedaction, "owned-tenant")
	var got incident.ImpactResponse
	if err := json.Unmarshal([]byte(redacted), &got); err != nil {
		t.Fatal(err)
	}
	if got.ContractVersion != value.ContractVersion || len(got.Customers) != 1 || strings.Contains(got.Customers[0].Value, "private-fixture") || strings.Contains(got.Customers[0].Value, "192.0.2.1") {
		t.Fatal("native impact changed its server contract or exempted operator prose")
	}
	for _, contract := range []string{"", "probectl.incident-impact.v2", "password=private-fixture", "host.example"} {
		value.ContractVersion = contract
		if body, err := marshalNativeIncidentImpact(value); err == nil || body != nil {
			t.Fatal("arbitrary contract text acquired structural encoding")
		}
	}
}
