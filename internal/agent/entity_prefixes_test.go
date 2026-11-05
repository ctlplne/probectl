// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package agent

import (
	"net/netip"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/ctlplne/probectl/internal/entity"
	agentv1 "github.com/ctlplne/probectl/internal/gen/probectl/agent/v1"
)

func TestSNMPPrefixEvidenceWireKeepsCompleteSetAndWholeRequestAdmission(t *testing.T) {
	client := &EvidenceClient{agentID: "agent", svc: agentv1.NewAgentServiceClient(nil)}
	now := time.Now()
	claim := entity.Observation{ID: "33333333-3333-4333-8333-333333333333",
		Source: entity.SourceKey{AgentID: "agent", Kind: entity.DeviceTarget, SourceRef: "192.0.2.1"},
		Alias:  entity.AliasKey{Kind: entity.AddressAlias, Value: "192.0.2.1"}, SourceRef: "snmp:configured-target", ObservedAt: now}
	for _, present := range []bool{false, true} {
		if present {
			for index := uint32(1); index <= 20000; index++ {
				claim.SNMPInterfacePrefixes = append(claim.SNMPInterfacePrefixes, entity.SNMPInterfacePrefix{
					IfIndex: index, Prefix: netip.MustParsePrefix("2001:db8::/32"), OnLink: index%2 == 0})
			}
		}
		request, err := client.encodeEvidence(now, []entity.Observation{claim})
		if err != nil || proto.Size(request) > 1<<20 {
			t.Fatal("complete prefix request was not encodable", err)
		}
		wire, err := proto.Marshal(request)
		if err != nil {
			t.Fatal(err)
		}
		var decoded agentv1.SubmitEntityEvidenceRequest
		if err := proto.Unmarshal(wire, &decoded); err != nil {
			t.Fatal(err)
		}
		set := decoded.Observations[0].SnmpInterfacePrefixes
		if (set != nil) != present {
			t.Fatal("prefix wire erased unavailable versus complete presence")
		}
		if !present {
			continue
		}
		if len(set.Prefixes) != len(claim.SNMPInterfacePrefixes) {
			t.Fatal("complete prefix wire silently lost rows")
		}
		for index, row := range set.Prefixes {
			expected := claim.SNMPInterfacePrefixes[index]
			if row.IfIndex != expected.IfIndex || row.Prefix != expected.Prefix.String() || row.OnLink != expected.OnLink {
				t.Fatal("complete prefix wire changed a field")
			}
		}
		// Three individually admissible whole snapshots overflow the complete
		// request. Refuse instead of sending a partial batch or prefix table.
		two, three := claim, claim
		two.ID, three.ID = "44444444-4444-4444-8444-444444444444", "55555555-5555-4555-8555-555555555555"
		if _, err := client.encodeEvidence(now, []entity.Observation{claim, two, three}); err == nil {
			t.Fatal("combined complete prefix request escaped whole-wire admission")
		}
	}
}
