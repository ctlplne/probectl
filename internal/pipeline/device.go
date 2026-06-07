package pipeline

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
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

	// Server-side tenant binding (TENANT-101) + siloed lanes (TENANT-107).
	binding   TenantBinding
	nsTenants map[string]string
	rejected  atomic.Uint64
}

// WithTenantBinding installs registry-backed tenant verification (TENANT-101).
func (c *DeviceConsumer) WithTenantBinding(b TenantBinding) *DeviceConsumer {
	c.binding = b
	return c
}

// WithNamespaceTenants adds each siloed tenant's namespaced device lane
// (TENANT-107); the lane is the authoritative tenant for its records.
func (c *DeviceConsumer) WithNamespaceTenants(ns map[string]string) *DeviceConsumer {
	c.nsTenants = ns
	return c
}

// RejectedBatches reports batches dropped by tenant verification.
func (c *DeviceConsumer) RejectedBatches() uint64 { return c.rejected.Load() }

// NewDeviceConsumer builds the consumer.
func NewDeviceConsumer(b bus.Bus, w tsdb.Writer, log *slog.Logger) *DeviceConsumer {
	if log == nil {
		log = slog.Default()
	}
	return &DeviceConsumer{bus: b, tsdb: w, group: DeviceGroup, log: log}
}

// Run subscribes until ctx is canceled (shared lane + one lane per siloed
// tenant). It blocks.
func (c *DeviceConsumer) Run(ctx context.Context) error {
	subs := []laneSub{{topic: bus.DeviceMetricsTopic, group: c.group}}
	for ns, tid := range c.nsTenants {
		t, err := bus.TopicFor(ns, bus.DeviceMetricsTopic)
		if err != nil {
			return err // RED-006: malformed namespace is fatal, never shared-lane
		}
		subs = append(subs, laneSub{topic: t, group: c.group + "-" + ns, laneTenant: tid})
	}
	c.log.Info("device pipeline consumer starting", "topic", bus.DeviceMetricsTopic, "group", c.group, "lanes", len(subs))
	ctx2, cancel := context.WithCancel(ctx)
	defer cancel()
	errs := make(chan error, len(subs))
	var wg sync.WaitGroup
	for _, s := range subs {
		wg.Add(1)
		go func(s laneSub) {
			defer wg.Done()
			h := func(hctx context.Context, msg bus.Message) error { return c.handleLane(hctx, msg, s.laneTenant) }
			if err := c.bus.Subscribe(ctx2, s.topic, s.group, h); err != nil && ctx2.Err() == nil {
				c.log.Error("device subscription failed", "topic", s.topic, "error", err.Error())
				errs <- err
				cancel()
			}
		}(s)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			return err
		}
	}
	return nil
}

// handleLane decodes one batch, VERIFIES its tenant (TENANT-101 — the
// payload is never authoritative), re-stamps, and writes its series.
// Unverifiable batches are dropped fail-closed and counted; transient write
// failures are logged and dropped (best-effort, matching the result pipeline).
func (c *DeviceConsumer) handleLane(ctx context.Context, msg bus.Message, laneTenant string) error {
	var batch devicev1.DeviceMetricBatch
	if err := proto.Unmarshal(msg.Value, &batch); err != nil {
		c.log.Error("dropping malformed device batch", "error", err.Error())
		return nil
	}
	if len(batch.Metrics) == 0 {
		return nil
	}
	ids := make([]Identity, len(batch.Metrics))
	for i, m := range batch.Metrics {
		ids[i] = Identity{Tenant: m.GetTenantId(), Agent: m.GetAgentId()}
	}
	tenant, overwritten, verr := VerifyBatchTenant(ctx, c.binding, laneTenant, ids)
	if verr != nil {
		c.rejected.Add(1)
		c.log.Error("REJECTED device batch: tenant verification failed (TENANT-101, fail closed)",
			"claimed_tenant", ids[0].Tenant, "agent_id", ids[0].Agent, "lane_tenant", laneTenant,
			"metrics", len(batch.Metrics), "rejected_total", c.rejected.Load(), "error", verr.Error())
		return nil
	}
	if overwritten {
		c.log.Warn("device batch tenant overwritten by lane (payload disagreed)",
			"claimed_tenant", ids[0].Tenant, "lane_tenant", tenant)
	}
	for _, m := range batch.Metrics {
		m.TenantId = tenant
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
