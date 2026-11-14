// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package pipeline

import (
	"fmt"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/ctlplne/probectl/internal/bus"
	"github.com/ctlplne/probectl/internal/fairness"
	devicev1 "github.com/ctlplne/probectl/internal/gen/probectl/device/v1"
	"github.com/ctlplne/probectl/internal/store/tsdb"
)

func TestOpticalDeviceConsumerKeepsTenantComponentAndChannelStorageDimensions(t *testing.T) {
	writer := tsdb.NewMemory()
	binding := &fakeBinding{pairs: map[[2]string]bool{{"tenant-a", "agent-a"}: true, {"tenant-b", "agent-b"}: true}}
	consumer := NewDeviceConsumer(nil, writer, testLogger()).WithTenantBinding(binding).WithFairness(fairness.NewGate(fairness.DefaultPolicy(), nil))
	for lane, tenant := range []string{"tenant-a", "tenant-b"} {
		agent := []string{"agent-a", "agent-b"}[lane]
		batch := &devicev1.DeviceMetricBatch{}
		for component := range 512 {
			for index, channel := range []string{"", "0", "1"} {
				for _, name := range []string{"probectl.device.optical.input.power.dbm", "probectl.device.optical.output.power.dbm", "probectl.device.optical.laser.bias.milliamperes"} {
					batch.Metrics = append(batch.Metrics, &devicev1.DeviceMetric{TenantId: tenant, AgentId: agent, DeviceAddress: "192.0.2.50", Source: "gnmi", Component: fmt.Sprintf("optic-%04d", component),
						PhysicalChannel: channel, Name: name, Value: 3.25 + float64(lane*10+index), TimeUnixNano: time.Now().UnixNano()})
				}
			}
			for _, name := range []string{"probectl.device.optical.supply.voltage.volts", "probectl.device.sensor.temperature.celsius"} {
				batch.Metrics = append(batch.Metrics, &devicev1.DeviceMetric{TenantId: tenant, AgentId: agent, DeviceAddress: "192.0.2.50", Source: "gnmi", Component: fmt.Sprintf("optic-%04d", component), Name: name, Value: 3.3, TimeUnixNano: time.Now().UnixNano()})
			}
		}
		raw, err := proto.Marshal(batch)
		if err != nil {
			t.Fatal(err)
		}
		if err := consumer.handleLane(t.Context(), bus.Message{Key: bus.TenantKey(tenant, agent), Value: raw}, bus.DeviceMetricsTopic, ""); err != nil {
			t.Fatal(err)
		}
		complete := 0
		for _, series := range writer.Snapshot() {
			if series.Labels["tenant_id"] == tenant {
				complete++
			}
		}
		if complete != 5632 {
			t.Fatal("complete512-component optical fleet lost admitted metric families", complete)
		}
		got := writer.Query("probectl_device_optical_input_power_dbm", map[string]string{"tenant_id": tenant})
		if len(got) != 1536 {
			t.Fatal("component aggregate/channel0/channel1 did not remain distinct under the tenant storage selector", len(got))
		}
		seen := map[string]bool{}
		for _, series := range got {
			if series.Labels["component"] == "" || series.Labels["agent_id"] != agent || series.Labels["if_name"] != "" || series.Labels["if_index"] != "" {
				t.Fatal("component metadata crossed tenant/agent scope or became a port", series.Labels)
			}
			seen[series.Labels["component"]+"/"+series.Labels["physical_channel"]] = true
		}
		if len(seen) != 1536 || !seen["optic-0511/"] || !seen["optic-0511/0"] || !seen["optic-0511/1"] {
			t.Fatal("original channel presence was lost", seen)
		}
	}
	before := writer.Len()
	forged, err := proto.Marshal(&devicev1.DeviceMetricBatch{Metrics: []*devicev1.DeviceMetric{{TenantId: "tenant-b", AgentId: "agent-a", DeviceAddress: "192.0.2.50", Component: "same-optic", Name: "probectl.device.optical.input.power.dbm", Value: 99}}})
	if err != nil {
		t.Fatal(err)
	}
	_ = consumer.handleLane(t.Context(), bus.Message{Key: bus.TenantKey("tenant-b", "agent-a"), Value: forged}, bus.DeviceMetricsTopic, "")
	if writer.Len() != before {
		t.Fatal("component labels bypassed tenant/agent admission")
	}
}
