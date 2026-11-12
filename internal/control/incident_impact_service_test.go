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
	"testing"
	"time"

	gouuid "github.com/google/uuid"

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
	value := incident.ImpactResponse{IncidentID: gouuid.NewString(), ObservedByteChange: "-55340232221128654845", Members: []incident.ImpactMember{}, Customers: []incident.ImpactCustomer{}, UnresolvedSignalIDs: []string{}}
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
