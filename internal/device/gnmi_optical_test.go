// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package device

import (
	"context"
	"io"
	"log/slog"
	"math"
	"net"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	gnmipb "github.com/ctlplne/probectl/internal/gen/gnmi"
)

func opticalDecimalWire(t *testing.T, digits int64, precision uint32) *gnmipb.TypedValue {
	t.Helper()
	decimal := protowire.AppendTag(nil, 1, protowire.VarintType)
	decimal = protowire.AppendVarint(decimal, uint64(digits))
	decimal = protowire.AppendTag(decimal, 2, protowire.VarintType)
	decimal = protowire.AppendVarint(decimal, uint64(precision))
	raw := protowire.AppendTag(nil, 7, protowire.BytesType)
	raw = protowire.AppendBytes(raw, decimal)
	value := &gnmipb.TypedValue{}
	if err := proto.Unmarshal(raw, value); err != nil {
		t.Fatal(err)
	}
	return value
}

type opticalGNMITarget struct {
	gnmipb.UnimplementedGNMIServer
	updates []*gnmipb.Update
}

func (target opticalGNMITarget) Subscribe(stream gnmipb.GNMI_SubscribeServer) error {
	if _, err := stream.Recv(); err != nil {
		return err
	}
	return stream.Send(&gnmipb.SubscribeResponse{Response: &gnmipb.SubscribeResponse_Update{Update: &gnmipb.Notification{
		Timestamp: pollTime.UnixNano(), Prefix: parsePath("/components/component[name=same-optic]"), Update: target.updates,
	}}})
}

func TestGNMIOpticalTLSRetainsComponentChannelZeroUnitsAndTenant(t *testing.T) {
	double := func(value float64) *gnmipb.TypedValue {
		return &gnmipb.TypedValue{Value: &gnmipb.TypedValue_DoubleVal{DoubleVal: value}}
	}
	updates := []*gnmipb.Update{
		{Path: parsePath("transceiver/state/input-power/instant"), Val: double(-3.25)},
		{Path: parsePath("transceiver/state/output-power/instant"), Val: opticalDecimalWire(t, 125, 2)},
		{Path: parsePath("transceiver/physical-channels/channel[index=0]/state/input-power/instant"), Val: double(-4.5)},
		{Path: parsePath("transceiver/physical-channels/channel[index=1]/state/input-power/instant"), Val: double(-5.75)},
		{Path: parsePath("transceiver/physical-channels/channel[index=0]/state/laser-bias-current/instant"), Val: double(11.01)},
		{Path: parsePath("transceiver/state/supply-voltage/instant"), Val: double(3.3)},
		{Path: parsePath("state/temperature/instant"), Val: double(42.5)},
	}
	for _, tenant := range []string{"tenant-a", "tenant-b"} {
		listener, ca := startTLSGNMITarget(t, opticalGNMITarget{updates: updates})
		emitter := &captureEmitter{}
		collector := &gnmiCollector{dev: Target{Address: "192.0.2.50", Port: 9339, Transport: TransportGNMI, GNMI: GNMIConfig{CAFile: ca, Paths: []string{"/components/component/transceiver"}, SampleInterval: time.Second}},
			tenant: tenant, agent: "owned-agent", emit: emitter, log: slog.New(slog.NewTextHandler(io.Discard, nil)), targetOverride: "passthrough:///bufnet",
			dialOpts: []grpc.DialOption{grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return listener.DialContext(ctx) })}}
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		_ = collector.streamOnce(ctx) // The modeled target closes after its one complete notification.
		cancel()
		metrics := emitter.snapshot()
		if len(metrics) != 7 {
			t.Fatal("typed optical notification was shortened", len(metrics))
		}
		seen := map[string]Metric{}
		for _, metric := range metrics {
			wire := metric.ToProto()
			if metric.TenantID != tenant || metric.Component != "same-optic" || metric.IfIndex != 0 || metric.IfName != "" || !metric.At.Equal(pollTime) || wire.GetComponent() != metric.Component || wire.GetPhysicalChannel() != metric.PhysicalChannel {
				t.Fatal("optical source lost scope/channel or invented a port", metric)
			}
			seen[metric.Name+"/"+metric.PhysicalChannel] = metric
		}
		if seen[MetricOpticalInputDBM+"/"].Value != -3.25 || seen[MetricOpticalOutputDBM+"/"].Value != 1.25 || seen[MetricOpticalInputDBM+"/0"].Value != -4.5 || seen[MetricOpticalInputDBM+"/1"].Value != -5.75 || seen[MetricOpticalBiasMA+"/0"].Unit != "mA" || seen[MetricOpticalVoltage+"/"].Unit != "V" || seen[MetricSensorCelsius+"/"].Value != 42.5 {
			t.Fatal("optical units were rescaled or distinct physical channels collapsed", seen)
		}
	}
	for _, value := range []*gnmipb.TypedValue{double(math.NaN()), double(math.Inf(1)), opticalDecimalWire(t, 1, ^uint32(0)), {Value: &gnmipb.TypedValue_BoolVal{BoolVal: false}}} {
		if _, valid := opticalScalarValue(value); valid {
			t.Fatal("unsupported numeric domain became an optical zero or finite observation")
		}
	}
}
