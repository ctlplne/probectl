// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/incident"
)

func TestICMPRoundTripReceiptsKeepOriginalCarrierAndInternetVerdicts(t *testing.T) {
	for _, family := range []struct {
		name    string
		fixture func(*testing.T) (context.Context, incidentVerdictEvidence)
		want    incident.FaultDomain
	}{{"carrier", carrierVerdictFixture, incident.FaultCarrier}, {"internet", internetVerdictFixture, incident.FaultWiderInternet}} {
		for _, mutation := range []string{"original", "missing samples", "wrong indexed clock"} {
			t.Run(family.name+"/"+mutation, func(t *testing.T) {
				ctx, input := family.fixture(t)
				for i := range input.tests {
					read := &input.tests[i].reads[0]
					m := read.ICMP
					m.Version = 3
					read.ObservedAt = m.CompletedAt.Truncate(time.Microsecond)
					m.CompletedAt = read.ObservedAt.Add(987 * time.Nanosecond)
					m.RoundTrips = &entity.ICMPRoundTrips{Nanos: make([]uint64, m.Replies), ExecutionNanos: uint64(m.CompletedAt.Sub(m.StartedAt))}
					for j := range m.NetworkErrors {
						m.NetworkErrors[j].ReceivedAt = m.CompletedAt
					}
					switch mutation {
					case "missing samples":
						m.RoundTrips = nil
					case "wrong indexed clock":
						read.ObservedAt = read.ObservedAt.Add(time.Microsecond)
					}
				}
				actual, err := classifyIncidentVerdict(ctx, input, 16<<20)
				want := family.want
				if mutation != "original" {
					want = incident.FaultUnknown
				}
				if err != nil || actual.Domain != want {
					t.Fatal("version3 changed original network verdict requirements", actual.Domain, want, err)
				}
			})
		}
	}
}
