// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/ai"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/incident"
	"github.com/ctlplne/probectl/internal/store"
)

func TestImpactExportRedactsLabelsWithoutChangingCountersOrCallerSnapshot(t *testing.T) {
	key, err := crypto.Random(32)
	if err != nil {
		t.Fatal(err)
	}
	input := incident.ImpactResponse{Customers: []incident.ImpactCustomer{{TagKey: "customer", Value: "alice@example.test 203.0.113.9", ContextID: "11111111-1111-4111-8111-111111111111", PrefixIDs: []string{"22222222-2222-4222-8222-222222222222"}}},
		Current: incident.ImpactPeriod{ObservedTotals: &incident.ImpactCounters{RawBytes: "18446744073709551615", RawPackets: "7", ScaledBytes: "55340232221128654845", ScaledPackets: "21"}}, ObservedByteChange: "-55340232221128654845"}
	output, err := redactIncidentImpact(input, ai.RedactionPolicy{MaskIPs: true, MaskPII: true, TokenKey: key}, "owned-tenant")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output.Customers[0].Value, "alice@example.test") || strings.Contains(output.Customers[0].Value, "203.0.113.9") || output.Customers[0].Value == input.Customers[0].Value {
		t.Fatal("export retained unredacted customer labels", output.Customers)
	}
	if input.Customers[0].Value != "alice@example.test 203.0.113.9" || output.Customers[0].ContextID != input.Customers[0].ContextID || output.Customers[0].PrefixIDs[0] != input.Customers[0].PrefixIDs[0] || *output.Current.ObservedTotals != *input.Current.ObservedTotals || output.ObservedByteChange != input.ObservedByteChange {
		t.Fatal("export changed exact counters, canonical citations or the caller snapshot")
	}
}

func TestImpactExportRejectsChangedRetainedSignalSourcesAndTenant(t *testing.T) {
	at := time.Now().UTC()
	for _, tenant := range []string{"tenant-red", "tenant-blue"} {
		inc := incident.Incident{ID: "owned-incident", TenantID: tenant, StartedAt: at, LastSeenAt: at, SignalCount: 1, IdentityLookupAttempted: true, IdentityContextID: "owned-context", IdentityEntityID: "root-device",
			Signals: []incident.Signal{{ID: "retained-signal", IdentityLookupAttempted: true, IdentityContextID: "owned-context", IdentityEntityID: "child-device"}}}
		snapshot := store.IncidentImpactInputs{TenantID: tenant, IncidentID: inc.ID, StartedAt: at, LastSeenAt: at, SignalCount: 1, Entities: []store.IncidentImpactEntity{
			{ContextID: "owned-context", EntityID: "root-device", IncidentRoot: true},
			{ContextID: "owned-context", EntityID: "child-device", SignalIDs: []string{"retained-signal"}},
		}}
		if err := requireImpactIncidentHeader(tenant, &inc, &snapshot); err != nil {
			t.Fatal("unchanged complete header was refused", err)
		}
		snapshot.Entities[1].EntityID = "replacement-device"
		if err := requireImpactIncidentHeader(tenant, &inc, &snapshot); err == nil || !strings.Contains(err.Error(), "signal source changed") {
			t.Fatal("same-count signal source replacement escaped export currentness", err)
		}
		snapshot.Entities[1].EntityID = "child-device"
		snapshot.TenantID = "foreign-" + tenant
		if err := requireImpactIncidentHeader(tenant, &inc, &snapshot); err == nil {
			t.Fatal("foreign snapshot entered this tenant's export")
		}
		snapshot.TenantID = tenant
		snapshot.Entities[0].IncidentRoot = false
		if err := requireImpactIncidentHeader(tenant, &inc, &snapshot); err == nil {
			t.Fatal("missing canonical root was treated as complete")
		}
	}
}
