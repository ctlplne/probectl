package pipeline

import (
	"context"
	"log/slog"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/imfeelingtheagi/probectl/internal/bus"
	devicev1 "github.com/imfeelingtheagi/probectl/internal/gen/probectl/device/v1"
	"github.com/imfeelingtheagi/probectl/internal/otel"
	"github.com/imfeelingtheagi/probectl/internal/store/tsdb"
)

// DeviceGroup is the consumer-group name for the device-telemetry pipeline.
const DeviceGroup = DefaultGroup + "-device"

// deviceMetricPrefix prefixes every device series (probectl.device.if.in.octets
// -> probectl_device_if_in_octets).
const deviceMetricPrefix = "probectl_device_"

// deviceLabelNames maps the OTel attributes promoted to (bounded-cardinality)
// labels — the ResultToSeries discipline applied to the device plane.
var deviceLabelNames = map[string]string{
	otel.AttrTenantID:      "tenant_id",
	otel.AttrAgentID:       "agent_id",
	otel.AttrDeviceAddress: "device",
	otel.AttrDeviceName:    "device_name",
	otel.AttrDeviceSource:  "source",
	otel.AttrDeviceIfIndex: "if_index",
	otel.AttrDeviceIfName:  "if_name",
}

// DeviceConsumer drains probectl.device.metrics into the TSDB, where the
// device plane becomes visible next to every other series (alerts, the AI
// query engine, dashboards).
type DeviceConsumer struct {
	bus   bus.Bus
	tsdb  tsdb.Writer
	group string
	log   *slog.Logger
}

// NewDeviceConsumer builds the consumer.
func NewDeviceConsumer(b bus.Bus, w tsdb.Writer, log *slog.Logger) *DeviceConsumer {
	if log == nil {
		log = slog.Default()
	}
	return &DeviceConsumer{bus: b, tsdb: w, group: DeviceGroup, log: log}
}

// Run subscribes until ctx is canceled. It blocks.
func (c *DeviceConsumer) Run(ctx context.Context) error {
	c.log.Info("device pipeline consumer starting", "topic", bus.DeviceMetricsTopic, "group", c.group)
	if err := c.bus.Subscribe(ctx, bus.DeviceMetricsTopic, c.group, c.handle); err != nil && ctx.Err() == nil {
		c.log.Error("device subscription failed", "error", err.Error())
		return err
	}
	return nil
}

// handle decodes one batch and writes its series. Malformed messages and
// transient write failures are logged and dropped (best-effort, matching the
// result pipeline).
func (c *DeviceConsumer) handle(ctx context.Context, msg bus.Message) error {
	var batch devicev1.DeviceMetricBatch
	if err := proto.Unmarshal(msg.Value, &batch); err != nil {
		c.log.Error("dropping malformed device batch", "error", err.Error())
		return nil
	}
	if len(batch.Metrics) == 0 {
		return nil
	}
	series := make([]tsdb.Series, 0, len(batch.Metrics))
	for _, m := range batch.Metrics {
		series = append(series, DeviceMetricToSeries(m))
	}
	if err := c.tsdb.Write(ctx, series); err != nil {
		c.log.Error("tsdb write failed", "tenant_id", batch.Metrics[0].GetTenantId(),
			"series", len(series), "error", err.Error())
	}
	return nil
}

// DeviceMetricToSeries converts one device sample into a TSDB series with
// OTel-aligned, cardinality-bounded labels.
func DeviceMetricToSeries(m *devicev1.DeviceMetric) tsdb.Series {
	attrs := otel.DeviceMetricAttributes(m)
	labels := make(map[string]string, len(deviceLabelNames))
	for otelKey, promName := range deviceLabelNames {
		if v, ok := attrs[otelKey]; ok {
			labels[promName] = v
		}
	}
	tms := m.GetTimeUnixNano() / int64(time.Millisecond)
	if tms == 0 {
		tms = time.Now().UnixMilli()
	}
	return tsdb.Series{
		Metric:     deviceMetricPrefix + sanitize(trimDevicePrefix(m.GetName())),
		Labels:     labels,
		Value:      m.GetValue(),
		TimeMillis: tms,
	}
}

// trimDevicePrefix drops the shared probectl.device. namespace before
// sanitizing, so series read probectl_device_<rest>.
func trimDevicePrefix(name string) string {
	const p = "probectl.device."
	if len(name) > len(p) && name[:len(p)] == p {
		return name[len(p):]
	}
	return name
}
