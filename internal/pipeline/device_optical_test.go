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

func TestVendorProfileDeviceMetricsKeepOriginalEvidenceInTenantStorage(t *testing.T) {
	writer := tsdb.NewMemory()
	binding := &fakeBinding{pairs: map[[2]string]bool{{"tenant-a", "agent-a"}: true, {"tenant-b", "agent-b"}: true}}
	consumer := NewDeviceConsumer(nil, writer, testLogger()).WithTenantBinding(binding)
	profile := &devicev1.DeviceSNMPMetricSource{ProfileId: "hpe-aruba-5406r",
		SystemObjectId: ".1.3.6.1.4.1.11.2.3.7.11.160", MibObject: "FAN-MIB::hpicfFanState", Oid: ".1.3.6.1.4.1.11.2.14.11.5.1.54.2.1.1.4"}
	for _, lane := range []struct {
		tenant, agent string
		value         float64
	}{{"tenant-a", "agent-a", 0}, {"tenant-b", "agent-b", 5}} {
		batch := &devicev1.DeviceMetricBatch{Metrics: []*devicev1.DeviceMetric{{
			TenantId: lane.tenant, AgentId: lane.agent, DeviceAddress: "192.0.2.50", Source: "snmp",
			Component: "4", Name: "probectl.device.fan.state", Value: lane.value, Unit: "1",
			SnmpMetricSource: profile, TimeUnixNano: time.Now().UnixNano(),
		}}}
		raw, err := proto.Marshal(batch)
		if err != nil {
			t.Fatal(err)
		}
		if err := consumer.handleLane(t.Context(), bus.Message{Key: bus.TenantKey(lane.tenant, lane.agent), Value: raw}, bus.DeviceMetricsTopic, ""); err != nil {
			t.Fatal(err)
		}
	}
	for _, lane := range []struct {
		tenant string
		value  float64
	}{{"tenant-a", 0}, {"tenant-b", 5}} {
		got := writer.Query("probectl_device_fan_state", map[string]string{"tenant_id": lane.tenant, "device": "192.0.2.50"})
		if len(got) != 1 || got[0].Value != lane.value {
			t.Fatal("vendor values crossed the tenant storage selector", got)
		}
		labels := got[0].Labels
		if labels["component"] != "4" || labels["snmp_profile"] != profile.ProfileId ||
			labels["snmp_system_object_id"] != profile.SystemObjectId || labels["snmp_oid"] != profile.Oid ||
			labels["snmp_mib_object"] != profile.MibObject || labels["snmp_unit"] != "1" {
			t.Fatal("stored samples lost their original MIB identity", labels)
		}
	}
}
