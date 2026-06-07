package pipeline

import (
	"context"
	"log/slog"
	"math/rand/v2"
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

	// Store-write resilience (Sprint 14, SCALE-008 residual): the device
	// plane now rides the SAME retry+DLQ contract as results — transient
	// TSDB failures retry with jittered backoff, exhaustion dead-letters the
	// ORIGINAL bytes, and loss is never silent.
	maxRetries   int
	retryBase    time.Duration
	sleep        func(context.Context, time.Duration)
	retried      atomic.Uint64
	deadLettered atomic.Uint64
	dropped      atomic.Uint64
}

// Dropped reports device batches lost entirely (DLQ publish ALSO failed).
func (c *DeviceConsumer) Dropped() uint64 { return c.dropped.Load() }

// DeadLettered reports device batches routed to the DLQ after exhaustion.
func (c *DeviceConsumer) DeadLettered() uint64 { return c.deadLettered.Load() }

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
	return &DeviceConsumer{
		bus: b, tsdb: w, group: DeviceGroup, log: log,
		maxRetries: 3, retryBase: 50 * time.Millisecond, sleep: sleepCtx,
	}
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
	// SCALE-008 residual: retry with jittered backoff; exhaustion routes the
	// ORIGINAL bytes to the device DLQ — never a silent drop.
	if err := c.writeWithRetry(ctx, series); err != nil {
		c.deadLetter(ctx, msg, tenant, err)
	}
	return nil
}

// writeWithRetry mirrors the results pipeline's policy (U-019).
func (c *DeviceConsumer) writeWithRetry(ctx context.Context, series []tsdb.Series) error {
	var err error
	for attempt := 0; ; attempt++ {
		if err = c.tsdb.Write(ctx, series); err == nil {
			return nil
		}
		if attempt >= c.maxRetries || ctx.Err() != nil {
			return err
		}
		c.retried.Add(1)
		backoff := c.retryBase << attempt
		c.sleep(ctx, backoff+time.Duration(rand.Int64N(int64(backoff)/2+1)))
	}
}

// deadLetter publishes the ORIGINAL message bytes to the device DLQ
// (tenant-keyed, replayable). A DLQ publish failure is the only true loss.
func (c *DeviceConsumer) deadLetter(ctx context.Context, msg bus.Message, tenant string, writeErr error) {
	if c.bus == nil {
		c.dropped.Add(1)
		c.log.Error("DEVICE BATCH LOST: write exhausted retries and no bus for the DLQ",
			"tenant_id", tenant, "write_error", writeErr.Error(), "dropped_total", c.dropped.Load())
		return
	}
	if err := c.bus.Publish(ctx, bus.DeadLetterDeviceTopic, msg.Key, msg.Value); err != nil {
		c.dropped.Add(1)
		c.log.Error("DEVICE BATCH LOST: write exhausted retries and dead-letter publish failed",
			"tenant_id", tenant, "write_error", writeErr.Error(), "dlq_error", err.Error(),
			"dropped_total", c.dropped.Load())
		return
	}
	c.deadLettered.Add(1)
	c.log.Warn("device batch dead-lettered after write retries",
		"tenant_id", tenant, "topic", bus.DeadLetterDeviceTopic, "write_error", writeErr.Error())
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
