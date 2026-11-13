// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"errors"
	"testing"

	googleuuid "github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/incident"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tags"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestIncidentCustomerUnionKeepsMeasuredTestSLOInputsAndUnknownCoverage(t *testing.T) {
	for _, tenant := range []string{"red", "blue"} {
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
		area, router, first, second, healthy, tagID := googleuuid.NewString(), googleuuid.NewString(), googleuuid.NewString(), googleuuid.NewString(), googleuuid.NewString(), googleuuid.NewString()
		failed, partial := googleuuid.NewString(), googleuuid.NewString()
		test := incident.ImpactTest{ContextID: area, EntityID: router, TestID: first, AgentID: "owned-agent",
			Current: incident.ImpactTestPeriod{Observations: []incident.ImpactTestObservation{
				{EvidenceID: failed, Status: "failed"},
				{EvidenceID: partial, Status: "successful", Packets: &incident.ImpactTestPackets{Lost: "2"}},
				{EvidenceID: googleuuid.NewString(), Status: "unknown", Packets: &incident.ImpactTestPackets{Lost: "100"}},
				{EvidenceID: googleuuid.NewString(), Status: "canceled"},
			}}, Previous: incident.ImpactTestPeriod{Observations: []incident.ImpactTestObservation{{EvidenceID: failed, Status: "failed"}}}}
		other := test
		other.TestID, other.Previous = second, incident.ImpactTestPeriod{}
		other.Current = incident.ImpactTestPeriod{Observations: []incident.ImpactTestObservation{{EvidenceID: partial, Status: "successful", Packets: &incident.ImpactTestPackets{Lost: "2"}}}}
		unhit := incident.ImpactTest{ContextID: area, EntityID: router, TestID: healthy, AgentID: "owned-agent", Current: incident.ImpactTestPeriod{Observations: []incident.ImpactTestObservation{{EvidenceID: googleuuid.NewString(), Status: "successful"}}}}
		metadata := &incidentTestCustomerTags{tenant: tenant, revision: 1, items: map[string]tags.SubjectResolution{}}
		for i, id := range []string{first, second} {
			value := "traffic-customer"
			if i == 1 {
				value = "test-only-customer"
			}
			metadata.items[id] = tags.SubjectResolution{ContextID: area, TargetKind: "test", TargetID: id, TagRevision: "1", Items: []tags.EffectiveItem{{TagID: tagID, Key: "customer", Value: value, Source: "manual"}}}
		}
		objective := incident.ImpactSLO{Name: "checkout-availability", Current: incident.ImpactSLOPeriod{Sources: []incident.ImpactSLOSource{{ContextID: area, EntityID: router, TestID: first, AgentID: "owned-agent", EvidenceIDs: []string{failed}}}}}
		base := []incident.ImpactCustomer{{TagKey: "customer", Value: "traffic-customer", ContextID: area, PrefixIDs: []string{googleuuid.NewString()}, TestIDs: []string{}, SLOIDs: []string{}, CaptureKeys: []string{"original-flow"}, Current: &incident.ImpactCounters{RawBytes: "18446744073709551616"}}}
		out, err := mergeIncidentTestCustomers(ctx, tenant, "customer", metadata, []incident.ImpactTest{test, other, unhit}, []incident.ImpactSLO{objective}, base, 1<<20)
		if err != nil || len(out) != 2 {
			t.Fatal("complete customer union unavailable", out, err)
		}
		for _, customer := range out {
			if len(customer.TestIDs) != 1 || len(customer.TagIDs) != 1 || customer.TagIDs[0] != tagID {
				t.Fatal("current tag/test provenance lost", customer)
			}
			if customer.Value == "traffic-customer" {
				if customer.Current == nil || customer.Current.RawBytes != "18446744073709551616" || len(customer.EvidenceIDs) != 2 || len(customer.SLOIDs) != 1 || customer.SLOIDs[0] != objective.Name || customer.TestIDs[0] != first || len(customer.CaptureKeys) != 1 || len(customer.PrefixIDs) != 1 {
					t.Fatal("overlap, unknown IO or SLO inputs changed observed traffic or citations", customer)
				}
			} else if customer.Value != "test-only-customer" || customer.Current != nil || customer.Previous != nil || len(customer.PrefixIDs) != 0 || len(customer.SLOIDs) != 0 || len(customer.EvidenceIDs) != 1 || customer.TestIDs[0] != second {
				t.Fatal("test-only input invented traffic volume or borrowed another SLO", customer)
			}
		}
		if len(base[0].TestIDs) != 0 || len(base[0].SLOIDs) != 0 {
			t.Fatal("union mutated its caller's captured traffic")
		}
		foreign := *metadata
		foreign.tenant = "foreign"
		if out, err := mergeIncidentTestCustomers(ctx, tenant, "customer", &foreign, []incident.ImpactTest{test}, nil, base, 1<<20); !errors.Is(err, entity.ErrScopeMismatch) || out != nil {
			t.Fatal("foreign metadata supplied a customer prefix", out, err)
		}
		if out, err := mergeIncidentTestCustomers(ctx, tenant, "customer", metadata, []incident.ImpactTest{test, other, unhit}, []incident.ImpactSLO{objective}, base, 4096); !errors.Is(err, flowstore.ErrExplorerBudget) || out != nil {
			t.Fatal("memory refusal returned a customer prefix", out, err)
		}
	}
}
