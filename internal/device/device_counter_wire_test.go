// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package device

import (
	"encoding/json"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	devicev1 "github.com/ctlplne/probectl/internal/gen/probectl/device/v1"
)

func TestDeviceCounterWireKeepsWholeUint64ZeroPresenceAndLegacyAbsence(t *testing.T) {
	for _, tenant := range []string{"red", "blue"} {
		for _, exact := range []CounterValue{{Value: 1<<53 + 1, Width: 64}, {Value: ^uint64(0), Width: 64}, {Value: 1<<32 - 1, Width: 32}, {Value: 0, Width: 32}} {
			metric := Metric{TenantID: tenant, AgentID: "same-agent", Device: "192.0.2.9", Source: SourceSNMP, IfIndex: 1<<32 - 1, Name: MetricIfInOctets, Value: float64(exact.Value), Unit: "octets", At: pollTime, ExactCounter: &CounterValue{Value: exact.Value, Width: exact.Width}}
			metric.ExactCounter.UptimeKnown, metric.ExactCounter.DiscontinuityKnown = true, true
			metric.ExactCounter.DiscontinuityTicks = 1<<32 - 1
			metric.ExactCounter.PollStartedAt, metric.ExactCounter.PollCompletedAt = pollTime, pollTime.Add(2*time.Second)
			wire := metric.ToProto()
			metric.ExactCounter.Value = 7
			metric.ExactCounter.UptimeTicks, metric.ExactCounter.DiscontinuityTicks = 9, 9
			if wire.ExactCounter == nil || wire.ExactCounter.Value != exact.Value || wire.ExactCounter.Width != exact.Width || wire.TenantId != tenant || wire.AgentId != metric.AgentID || wire.IfIndex != metric.IfIndex {
				t.Fatal("device metric wire omitted or rounded the original exact counter", wire)
			}
			if wire.ExactCounter.UptimeTicks == nil || *wire.ExactCounter.UptimeTicks != 0 || wire.ExactCounter.DiscontinuityTicks == nil || *wire.ExactCounter.DiscontinuityTicks != 1<<32-1 || wire.ExactCounter.PollStartedAtUnixNano != pollTime.UnixNano() || wire.ExactCounter.PollCompletedAtUnixNano != pollTime.Add(2*time.Second).UnixNano() {
				t.Fatal("device counter wire lost known zero, full clock width, owned copies or original poll bounds", wire)
			}
			raw, err := proto.Marshal(wire)
			if err != nil {
				t.Fatal(err)
			}
			var roundTrip devicev1.DeviceMetric
			if err := proto.Unmarshal(raw, &roundTrip); err != nil || roundTrip.ExactCounter == nil || roundTrip.ExactCounter.Value != exact.Value || roundTrip.ExactCounter.Width != exact.Width || roundTrip.TenantId != tenant {
				t.Fatal("device counter binary round trip lost exact width/value/zero presence or tenant", &roundTrip, err)
			}
			if !proto.Equal(wire, &roundTrip) {
				t.Fatal("counter round trip changed original raw clock presence or observation window")
			}
			if exact.Value == ^uint64(0) {
				encoded, err := protojson.Marshal(&roundTrip)
				if err != nil {
					t.Fatal(err)
				}
				var document struct {
					Counter struct {
						Value string `json:"value"`
					} `json:"exactCounter"`
				}
				if err := json.Unmarshal(encoded, &document); err != nil || document.Counter.Value != "18446744073709551615" {
					t.Fatal("device counter JSON passed an original uint64 through a rounded number", document, err)
				}
			}
			metric.ExactCounter = &CounterValue{Value: exact.Value, Width: exact.Width}
			unknown := metric.ToProto()
			if unknown.ExactCounter == nil || unknown.ExactCounter.UptimeTicks != nil || unknown.ExactCounter.DiscontinuityTicks != nil || unknown.ExactCounter.PollStartedAtUnixNano != 0 || unknown.ExactCounter.PollCompletedAtUnixNano != 0 {
				t.Fatal("unreported device clock invented known zero or a poll window", unknown)
			}
			metric.ExactCounter = nil
			legacy, err := proto.Marshal(metric.ToProto())
			if err != nil {
				t.Fatal(err)
			}
			var absent devicev1.DeviceMetric
			if err := proto.Unmarshal(legacy, &absent); err != nil || absent.ExactCounter != nil || absent.Value != metric.Value || absent.TenantId != tenant {
				t.Fatal("legacy double-only metric invented an exact zero counter or changed scope", &absent, err)
			}
		}
	}
}
