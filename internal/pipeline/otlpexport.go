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

	collogspb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	colmetricspb "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	coltracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	"google.golang.org/protobuf/proto"

	"github.com/ctlplne/probectl/internal/bus"
)

// MetricsExporter forwards an OTLP metrics request to an external collector.
// internal/otel/otlp.{GRPC,HTTP}Exporter implement it; the interface keeps the
// pipeline decoupled from the exporter transport.
type MetricsExporter interface {
	ExportMetrics(ctx context.Context, req *colmetricspb.ExportMetricsServiceRequest) error
}

// TracesExporter / LogsExporter forward OTLP traces / logs to an external
// collector (ARCH-003: traces+logs are now first-class re-export, not
// ingest-only). otlp.{GRPC,HTTP}Exporter implement all three.
type TracesExporter interface {
	ExportTraces(ctx context.Context, req *coltracepb.ExportTraceServiceRequest) error
}

type LogsExporter interface {
	ExportLogs(ctx context.Context, req *collogspb.ExportLogsServiceRequest) error
}

// OTLPExportConsumer drains the ingested OTLP-metrics topic and re-exports each
// (already tenant-stamped) batch to an external collector (ARCH-007). This is
// the config-driven export pipeline that makes the dormant exporter live: the
// platform can fan ingested OTLP back out to a customer's own backend without
// a separate collector hop. A failed export is logged + counted and the record
// is left UNMARKED so the at-least-once consumer redelivers it (no silent loss).
type OTLPExportConsumer struct {
	bus      bus.Bus
	exporter MetricsExporter
	router   *TenantExportRouter // RTP-06: per-tenant endpoints (nil = shared single endpoint)
	group    string
	log      *slog.Logger
	exported atomic.Uint64
	failed   atomic.Uint64
	dropped  atomic.Uint64

	nsTenants map[string]string
}

// NewOTLPExportConsumer builds the consumer over a shared exporter (the single/
// sovereign profile's one endpoint). A multi-tenant/regulated deployment passes
// a nil exporter here and supplies per-tenant endpoints via WithTenantRouter.
func NewOTLPExportConsumer(b bus.Bus, exp MetricsExporter, log *slog.Logger) *OTLPExportConsumer {
	if log == nil {
		log = slog.Default()
	}
	return &OTLPExportConsumer{bus: b, exporter: exp, group: DefaultGroup + "-otlp-export", log: log}
}

// exported / failed / dropped report cumulative export outcomes (observability).
func (c *OTLPExportConsumer) exportedCount() uint64 { return c.exported.Load() }
func (c *OTLPExportConsumer) failedCount() uint64   { return c.failed.Load() }
func (c *OTLPExportConsumer) droppedCount() uint64  { return c.dropped.Load() }

// WithNamespaceTenants subscribes the exporter to each siloed tenant's OTLP
// metrics lane and verifies/restamps resource tenants before forwarding.
func (c *OTLPExportConsumer) WithNamespaceTenants(ns map[string]string) *OTLPExportConsumer {
	c.nsTenants = ns
	return c
}

// WithTenantRouter routes each tenant's metrics to that tenant's OWN collector
// endpoint (RTP-06). When set it takes precedence over the shared exporter, and
// a tenant with no configured endpoint is dropped closed — never forwarded to
// another tenant's or the provider's collector.
func (c *OTLPExportConsumer) WithTenantRouter(r *TenantExportRouter) *OTLPExportConsumer {
	c.router = r
	return c
}

// Run subscribes until ctx is canceled. It blocks.
func (c *OTLPExportConsumer) Run(ctx context.Context) error {
	c.log.Info("otlp export consumer starting", "topic", bus.OTLPMetricsTopic, "group", c.group, "lanes", len(c.nsTenants)+1)
	return RunLanes(ctx, c.bus, bus.OTLPMetricsTopic, c.group, c.nsTenants, c.handleLane)
}

func (c *OTLPExportConsumer) handle(ctx context.Context, msg bus.Message) error {
	return c.handleLane(ctx, msg, "")
}

func (c *OTLPExportConsumer) handleLane(ctx context.Context, msg bus.Message, laneTenant string) error {
	var req colmetricspb.ExportMetricsServiceRequest
	if err := proto.Unmarshal(msg.Value, &req); err != nil {
		c.log.Warn("otlp-export: skipping malformed metrics payload", "error", err)
		return nil // poison message: drop (counted as handled), never wedge
	}
	tenant := otlpTenantFromLaneOrKey(msg, laneTenant)
	if tenant != "" {
		if err := scopeOTLPMetricsToBusTenant(&req, tenant); err != nil {
			c.log.Warn("otlp-export: skipping metrics payload outside lane tenant", "tenant_id", tenant, "error", err.Error())
			return nil
		}
	}
	exp, ok := c.resolveExporter(tenant)
	if !ok {
		c.dropped.Add(1)
		c.log.Warn("otlp-export: dropping metrics for a tenant with no per-tenant export endpoint (fail closed; RTP-06)", "tenant_id", tenant)
		return nil
	}
	// RTP-06: apply the storage-equivalent redaction before egress so a secret /
	// Authorization header / URL token that the STORE path masks never leaves to
	// the external collector in the clear.
	redactMetricsForExport(ctx, &req, tenant)
	if err := exp.ExportMetrics(ctx, &req); err != nil {
		c.failed.Add(1)
		c.log.Error("otlp-export: forward to external collector failed (will redeliver)", "error", err.Error())
		return err // leave uncommitted → at-least-once redelivery
	}
	c.exported.Add(1)
	return nil
}

// resolveExporter picks the per-tenant endpoint when a router is configured
// (RTP-06), else the shared single endpoint. A router without an entry for the
// tenant returns (nil,false) so the record is dropped closed.
func (c *OTLPExportConsumer) resolveExporter(tenant string) (MetricsExporter, bool) {
	if c.router != nil {
		return c.router.exporterFor(tenant)
	}
	return c.exporter, c.exporter != nil
}

// OTLPTraceExportConsumer drains the ingested OTLP-traces topic and re-exports
// each (already tenant-stamped) batch to an external collector (ARCH-003). Same
// at-least-once semantics as the metrics export consumer.
type OTLPTraceExportConsumer struct {
	bus      bus.Bus
	exporter TracesExporter
	router   *TenantExportRouter // RTP-06: per-tenant endpoints (nil = shared single endpoint)
	group    string
	log      *slog.Logger
	exported atomic.Uint64
	failed   atomic.Uint64
	dropped  atomic.Uint64

	nsTenants map[string]string
}

// NewOTLPTraceExportConsumer builds the consumer over a shared exporter; a
// multi-tenant/regulated deployment supplies per-tenant endpoints via
// WithTenantRouter instead.
func NewOTLPTraceExportConsumer(b bus.Bus, exp TracesExporter, log *slog.Logger) *OTLPTraceExportConsumer {
	if log == nil {
		log = slog.Default()
	}
	return &OTLPTraceExportConsumer{bus: b, exporter: exp, group: DefaultGroup + "-otlp-trace-export", log: log}
}

func (c *OTLPTraceExportConsumer) exportedCount() uint64 { return c.exported.Load() }
func (c *OTLPTraceExportConsumer) droppedCount() uint64  { return c.dropped.Load() }

// WithNamespaceTenants subscribes the exporter to each siloed tenant's OTLP
// trace lane and verifies/restamps resource tenants before forwarding.
func (c *OTLPTraceExportConsumer) WithNamespaceTenants(ns map[string]string) *OTLPTraceExportConsumer {
	c.nsTenants = ns
	return c
}

// WithTenantRouter routes each tenant's traces to that tenant's OWN collector
// endpoint (RTP-06); a tenant with no endpoint is dropped closed.
func (c *OTLPTraceExportConsumer) WithTenantRouter(r *TenantExportRouter) *OTLPTraceExportConsumer {
	c.router = r
	return c
}

func (c *OTLPTraceExportConsumer) resolveExporter(tenant string) (TracesExporter, bool) {
	if c.router != nil {
		return c.router.exporterFor(tenant)
	}
	return c.exporter, c.exporter != nil
}

// Run subscribes until ctx is canceled. It blocks.
func (c *OTLPTraceExportConsumer) Run(ctx context.Context) error {
	c.log.Info("otlp trace export consumer starting", "topic", bus.OTLPTracesTopic, "group", c.group, "lanes", len(c.nsTenants)+1)
	return RunLanes(ctx, c.bus, bus.OTLPTracesTopic, c.group, c.nsTenants, c.handleLane)
}

func (c *OTLPTraceExportConsumer) handle(ctx context.Context, msg bus.Message) error {
	return c.handleLane(ctx, msg, "")
}

func (c *OTLPTraceExportConsumer) handleLane(ctx context.Context, msg bus.Message, laneTenant string) error {
	var req coltracepb.ExportTraceServiceRequest
	if err := proto.Unmarshal(msg.Value, &req); err != nil {
		c.log.Warn("otlp-export: skipping malformed traces payload", "error", err)
		return nil
	}
	tenant := otlpTenantFromLaneOrKey(msg, laneTenant)
	if tenant != "" {
		if err := scopeOTLPTracesToBusTenant(&req, tenant); err != nil {
			c.log.Warn("otlp-export: skipping traces payload outside lane tenant", "tenant_id", tenant, "error", err.Error())
			return nil
		}
	}
	exp, ok := c.resolveExporter(tenant)
	if !ok {
		c.dropped.Add(1)
		c.log.Warn("otlp-export: dropping traces for a tenant with no per-tenant export endpoint (fail closed; RTP-06)", "tenant_id", tenant)
		return nil
	}
	redactTracesForExport(ctx, &req, tenant)
	if err := exp.ExportTraces(ctx, &req); err != nil {
		c.failed.Add(1)
		c.log.Error("otlp-export: forward traces to external collector failed (will redeliver)", "error", err.Error())
		return err
	}
	c.exported.Add(1)
	return nil
}

// OTLPLogExportConsumer drains the ingested OTLP-logs topic and re-exports each
// (already tenant-stamped) batch to an external collector (ARCH-003).
type OTLPLogExportConsumer struct {
	bus      bus.Bus
	exporter LogsExporter
	router   *TenantExportRouter // RTP-06: per-tenant endpoints (nil = shared single endpoint)
	group    string
	log      *slog.Logger
	exported atomic.Uint64
	failed   atomic.Uint64
	dropped  atomic.Uint64

	nsTenants map[string]string
}

// NewOTLPLogExportConsumer builds the consumer over a shared exporter; a
// multi-tenant/regulated deployment supplies per-tenant endpoints via
// WithTenantRouter instead.
func NewOTLPLogExportConsumer(b bus.Bus, exp LogsExporter, log *slog.Logger) *OTLPLogExportConsumer {
	if log == nil {
		log = slog.Default()
	}
	return &OTLPLogExportConsumer{bus: b, exporter: exp, group: DefaultGroup + "-otlp-log-export", log: log}
}

func (c *OTLPLogExportConsumer) exportedCount() uint64 { return c.exported.Load() }
func (c *OTLPLogExportConsumer) droppedCount() uint64  { return c.dropped.Load() }

// WithNamespaceTenants subscribes the exporter to each siloed tenant's OTLP log
// lane and verifies/restamps resource tenants before forwarding.
func (c *OTLPLogExportConsumer) WithNamespaceTenants(ns map[string]string) *OTLPLogExportConsumer {
	c.nsTenants = ns
	return c
}

// WithTenantRouter routes each tenant's logs to that tenant's OWN collector
// endpoint (RTP-06); a tenant with no endpoint is dropped closed.
func (c *OTLPLogExportConsumer) WithTenantRouter(r *TenantExportRouter) *OTLPLogExportConsumer {
	c.router = r
	return c
}

func (c *OTLPLogExportConsumer) resolveExporter(tenant string) (LogsExporter, bool) {
	if c.router != nil {
		return c.router.exporterFor(tenant)
	}
	return c.exporter, c.exporter != nil
}

// Run subscribes until ctx is canceled. It blocks.
func (c *OTLPLogExportConsumer) Run(ctx context.Context) error {
	c.log.Info("otlp log export consumer starting", "topic", bus.OTLPLogsTopic, "group", c.group, "lanes", len(c.nsTenants)+1)
	return RunLanes(ctx, c.bus, bus.OTLPLogsTopic, c.group, c.nsTenants, c.handleLane)
}

func (c *OTLPLogExportConsumer) handle(ctx context.Context, msg bus.Message) error {
	return c.handleLane(ctx, msg, "")
}

func (c *OTLPLogExportConsumer) handleLane(ctx context.Context, msg bus.Message, laneTenant string) error {
	var req collogspb.ExportLogsServiceRequest
	if err := proto.Unmarshal(msg.Value, &req); err != nil {
		c.log.Warn("otlp-export: skipping malformed logs payload", "error", err)
		return nil
	}
	tenant := otlpTenantFromLaneOrKey(msg, laneTenant)
	if tenant != "" {
		if err := scopeOTLPLogsToBusTenant(&req, tenant); err != nil {
			c.log.Warn("otlp-export: skipping logs payload outside lane tenant", "tenant_id", tenant, "error", err.Error())
			return nil
		}
	}
	exp, ok := c.resolveExporter(tenant)
	if !ok {
		c.dropped.Add(1)
		c.log.Warn("otlp-export: dropping logs for a tenant with no per-tenant export endpoint (fail closed; RTP-06)", "tenant_id", tenant)
		return nil
	}
	redactLogsForExport(ctx, &req, tenant)
	if err := exp.ExportLogs(ctx, &req); err != nil {
		c.failed.Add(1)
		c.log.Error("otlp-export: forward logs to external collector failed (will redeliver)", "error", err.Error())
		return err
	}
	c.exported.Add(1)
	return nil
}
