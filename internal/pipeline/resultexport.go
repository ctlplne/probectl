// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package pipeline

import (
	"context"
	"log/slog"
	"sync/atomic"

	"google.golang.org/protobuf/proto"

	"github.com/ctlplne/probectl/internal/bus"
	resultv1 "github.com/ctlplne/probectl/internal/gen/probectl/result/v1"
	"github.com/ctlplne/probectl/internal/otel/otlp"
)

// ResultOTLPExportConsumer drains the network/probe result topic
// (bus.NetworkResultsTopic) and re-exports each probe result as OTLP metrics to
// an external collector (RTP-07). probectl emits its OWN probe signals
// (probectl.probe.success / probectl.probe.duration) as OTLP — "probectl
// observes probectl" — so the self-observability claim is a live export path,
// not a dormant doc assertion: with OTLP export enabled, each canary result
// reaches the collector within one flush.
//
// Tenant-FIRST (docs/guardrails.md G7-1): the bus-key / namespaced-lane tenant
// is authoritative, NEVER the payload's tenant_id. A record whose payload tenant
// differs from the lane/key tenant, or that arrives unkeyed (no authoritative
// tenant at all), is dropped and counted — a spoofed payload can never ride the
// authoritative lane. At-least-once: a malformed payload is dropped without
// wedging the stream; an export failure returns an error so the consumer
// redelivers (and is counted), never a silent loss.
type ResultOTLPExportConsumer struct {
	bus      bus.Bus
	exporter MetricsExporter
	group    string
	log      *slog.Logger
	exported atomic.Uint64
	failed   atomic.Uint64
	dropped  atomic.Uint64

	nsTenants map[string]string
}

// NewResultOTLPExportConsumer builds the consumer over a non-nil metrics
// exporter (the real otlp.{HTTP,GRPC}Exporter satisfies MetricsExporter).
func NewResultOTLPExportConsumer(b bus.Bus, exp MetricsExporter, log *slog.Logger) *ResultOTLPExportConsumer {
	if log == nil {
		log = slog.Default()
	}
	return &ResultOTLPExportConsumer{bus: b, exporter: exp, group: DefaultGroup + "-result-otlp-export", log: log}
}

// exported / failed / dropped report cumulative outcomes (self-observability).
func (c *ResultOTLPExportConsumer) exportedCount() uint64 { return c.exported.Load() }
func (c *ResultOTLPExportConsumer) failedCount() uint64   { return c.failed.Load() }
func (c *ResultOTLPExportConsumer) droppedCount() uint64  { return c.dropped.Load() }

// WithNamespaceTenants subscribes the exporter to each siloed tenant's probe
// result lane; on a namespaced lane the lane tenant is authoritative and
// overrides the payload (TENANT-101).
func (c *ResultOTLPExportConsumer) WithNamespaceTenants(ns map[string]string) *ResultOTLPExportConsumer {
	c.nsTenants = ns
	return c
}

// Run subscribes the shared lane plus every siloed-tenant lane until ctx is
// canceled. It blocks.
func (c *ResultOTLPExportConsumer) Run(ctx context.Context) error {
	c.log.Info("result otlp export consumer starting", "topic", bus.NetworkResultsTopic, "group", c.group, "lanes", len(c.nsTenants)+1)
	return RunLanes(ctx, c.bus, bus.NetworkResultsTopic, c.group, c.nsTenants, c.handleLane)
}

func (c *ResultOTLPExportConsumer) handle(ctx context.Context, msg bus.Message) error {
	return c.handleLane(ctx, msg, "")
}

func (c *ResultOTLPExportConsumer) handleLane(ctx context.Context, msg bus.Message, laneTenant string) error {
	var r resultv1.Result
	if err := proto.Unmarshal(msg.Value, &r); err != nil {
		c.log.Warn("result-otlp-export: skipping malformed result payload", "error", err)
		return nil // poison message: drop (counted as handled), never wedge the stream
	}
	// Tenant-FIRST: resolve the authoritative tenant from the namespaced lane
	// or the bus key — NEVER from the payload (docs/guardrails.md G7-1).
	tenant := otlpTenantFromLaneOrKey(msg, laneTenant)
	if tenant == "" {
		c.dropped.Add(1)
		c.log.Warn("result-otlp-export: dropping unkeyed result (no authoritative tenant; fail closed)", "topic", msg.Topic)
		return nil
	}
	if r.GetTenantId() != tenant {
		c.dropped.Add(1)
		c.log.Warn("result-otlp-export: dropping result whose payload tenant differs from the authoritative lane/key tenant (G7-1)",
			"authoritative_tenant", tenant, "payload_tenant", r.GetTenantId(), "topic", msg.Topic)
		return nil
	}
	// The authoritative tenant governs the exported resource attributes; the
	// payload matched it above, so the OTLP metric carries the bus-key tenant.
	r.TenantId = tenant
	if err := c.exporter.ExportMetrics(ctx, otlp.MetricsForResult(&r)); err != nil {
		c.failed.Add(1)
		c.log.Error("result-otlp-export: forward probe metrics to external collector failed (will redeliver)", "error", err.Error())
		return err // leave uncommitted → at-least-once redelivery
	}
	c.exported.Add(1)
	return nil
}
