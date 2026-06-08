package pipeline

import (
	"context"
	"encoding/hex"
	"log/slog"
	"strconv"
	"sync/atomic"
	"time"

	collogspb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	coltracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
	"google.golang.org/protobuf/proto"

	"github.com/imfeelingtheagi/probectl/internal/bus"
	"github.com/imfeelingtheagi/probectl/internal/store/otelstore"
)

// OTLP traces + logs consumers (ARCH-001, Sprint 22): the receiver
// authenticates, tenant-scopes, and publishes each signal to its topic;
// these consumers drain the topics into the otelstore — the same
// receiver→bus→consumer→store shape as the Sprint 16 metrics plane, so all
// three OTLP signals are received + stored + queryable. Attribute sets are
// bounded at conversion (cardinality stance, U-017).

// otlpMaxAttrs bounds per-row stored attributes (resource + point, busiest
// first deterministically — sorted merge like the metrics plane).
const otlpMaxAttrs = 12

// otlpMaxBody bounds a stored log body (a log line, not a blob store).
const otlpMaxBody = 8 << 10

// OTLPTraceConsumer drains probectl.otlp.traces into the otelstore.
type OTLPTraceConsumer struct {
	bus      bus.Bus
	store    otelstore.Store
	log      *slog.Logger
	consumed atomic.Uint64
}

// NewOTLPTraceConsumer builds the consumer.
func NewOTLPTraceConsumer(b bus.Bus, st otelstore.Store, log *slog.Logger) *OTLPTraceConsumer {
	if log == nil {
		log = slog.Default()
	}
	return &OTLPTraceConsumer{bus: b, store: st, log: log}
}

// Run subscribes until ctx is canceled. It blocks.
func (c *OTLPTraceConsumer) Run(ctx context.Context) error {
	c.log.Info("otlp traces consumer starting", "topic", bus.OTLPTracesTopic)
	return c.bus.Subscribe(ctx, bus.OTLPTracesTopic, "otlp-traces", c.handle)
}

// Consumed reports stored spans (the round-trip test's hook).
func (c *OTLPTraceConsumer) Consumed() uint64 { return c.consumed.Load() }

func (c *OTLPTraceConsumer) handle(ctx context.Context, msg bus.Message) error {
	var req coltracepb.ExportTraceServiceRequest
	if err := proto.Unmarshal(msg.Value, &req); err != nil {
		c.log.Warn("dropping malformed OTLP traces payload", "error", err.Error())
		return nil
	}
	tenant := string(tenantFromKey(msg.Key))
	spans := convertSpans(&req, tenant)
	if len(spans) == 0 {
		return nil
	}
	if err := c.store.WriteSpans(ctx, spans); err != nil {
		c.log.Error("otlp spans write failed", "spans", len(spans), "error", err.Error())
		return nil // best-effort, matching the metrics consumer's contract
	}
	c.consumed.Add(uint64(len(spans)))
	return nil
}

// convertSpans flattens ResourceSpans into store rows. The receiver already
// stamped/verified the tenant resource attribute; the bus key carries the
// same tenant.
func convertSpans(req *coltracepb.ExportTraceServiceRequest, tenant string) []otelstore.Span {
	var out []otelstore.Span
	for _, rs := range req.GetResourceSpans() {
		resAttrs, service, resTenant := resourceInfo(rs.GetResource().GetAttributes())
		if resTenant != "" {
			tenant = resTenant // the receiver-stamped truth wins over the bus key
		}
		for _, ss := range rs.GetScopeSpans() {
			for _, sp := range ss.GetSpans() {
				start := time.Unix(0, int64(sp.GetStartTimeUnixNano())).UTC()
				dur := time.Duration(int64(sp.GetEndTimeUnixNano()) - int64(sp.GetStartTimeUnixNano()))
				if dur < 0 {
					dur = 0
				}
				attrs := boundedAttrs(resAttrs, sp.GetAttributes())
				out = append(out, otelstore.Span{
					TenantID:     tenant,
					TraceID:      hex.EncodeToString(sp.GetTraceId()),
					SpanID:       hex.EncodeToString(sp.GetSpanId()),
					ParentSpanID: hex.EncodeToString(sp.GetParentSpanId()),
					Name:         sp.GetName(),
					Kind:         spanKind(sp.GetKind()),
					Service:      service,
					Start:        start,
					Duration:     dur,
					StatusCode:   statusCode(sp.GetStatus()),
					Attrs:        attrs,
				})
			}
		}
	}
	return out
}

// OTLPLogConsumer drains probectl.otlp.logs into the otelstore.
type OTLPLogConsumer struct {
	bus      bus.Bus
	store    otelstore.Store
	log      *slog.Logger
	consumed atomic.Uint64
}

// NewOTLPLogConsumer builds the consumer.
func NewOTLPLogConsumer(b bus.Bus, st otelstore.Store, log *slog.Logger) *OTLPLogConsumer {
	if log == nil {
		log = slog.Default()
	}
	return &OTLPLogConsumer{bus: b, store: st, log: log}
}

// Run subscribes until ctx is canceled. It blocks.
func (c *OTLPLogConsumer) Run(ctx context.Context) error {
	c.log.Info("otlp logs consumer starting", "topic", bus.OTLPLogsTopic)
	return c.bus.Subscribe(ctx, bus.OTLPLogsTopic, "otlp-logs", c.handle)
}

// Consumed reports stored records (the round-trip test's hook).
func (c *OTLPLogConsumer) Consumed() uint64 { return c.consumed.Load() }

func (c *OTLPLogConsumer) handle(ctx context.Context, msg bus.Message) error {
	var req collogspb.ExportLogsServiceRequest
	if err := proto.Unmarshal(msg.Value, &req); err != nil {
		c.log.Warn("dropping malformed OTLP logs payload", "error", err.Error())
		return nil
	}
	tenant := string(tenantFromKey(msg.Key))
	recs := convertLogs(&req, tenant)
	if len(recs) == 0 {
		return nil
	}
	if err := c.store.WriteLogs(ctx, recs); err != nil {
		c.log.Error("otlp logs write failed", "records", len(recs), "error", err.Error())
		return nil
	}
	c.consumed.Add(uint64(len(recs)))
	return nil
}

// convertLogs flattens ResourceLogs into store rows.
func convertLogs(req *collogspb.ExportLogsServiceRequest, tenant string) []otelstore.LogRecord {
	var out []otelstore.LogRecord
	for _, rl := range req.GetResourceLogs() {
		resAttrs, service, resTenant := resourceInfo(rl.GetResource().GetAttributes())
		if resTenant != "" {
			tenant = resTenant
		}
		for _, sl := range rl.GetScopeLogs() {
			for _, lr := range sl.GetLogRecords() {
				ts := lr.GetTimeUnixNano()
				if ts == 0 {
					ts = lr.GetObservedTimeUnixNano()
				}
				body := anyValueString(lr.GetBody())
				if len(body) > otlpMaxBody {
					body = body[:otlpMaxBody]
				}
				out = append(out, otelstore.LogRecord{
					TenantID:     tenant,
					TS:           time.Unix(0, int64(ts)).UTC(),
					SeverityNum:  int32(lr.GetSeverityNumber()),
					SeverityText: lr.GetSeverityText(),
					Service:      service,
					Body:         body,
					TraceID:      hex.EncodeToString(lr.GetTraceId()),
					SpanID:       hex.EncodeToString(lr.GetSpanId()),
					Attrs:        boundedAttrs(resAttrs, lr.GetAttributes()),
				})
			}
		}
	}
	return out
}

// --- shared conversion helpers ---

// resourceInfo extracts string resource attributes, the service name, and
// the receiver-stamped tenant.
func resourceInfo(kvs []*commonpb.KeyValue) (attrs map[string]string, service, tenant string) {
	attrs = map[string]string{}
	for _, kv := range kvs {
		v := anyValueString(kv.GetValue())
		if v == "" {
			continue
		}
		switch kv.GetKey() {
		case "service.name":
			service = v
		case "probectl.tenant.id":
			tenant = v
			continue // the tenant column carries it; never an attribute
		}
		attrs[kv.GetKey()] = v
	}
	return attrs, service, tenant
}

// boundedAttrs merges resource + record attributes up to otlpMaxAttrs,
// deterministically (sorted), mirroring the metrics plane's label bound.
func boundedAttrs(res map[string]string, kvs []*commonpb.KeyValue) map[string]string {
	merged := map[string]string{}
	addSorted := func(m map[string]string) {
		keys := make([]string, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		sortStrings(keys)
		for _, k := range keys {
			if len(merged) >= otlpMaxAttrs {
				return
			}
			if _, ok := merged[k]; !ok {
				merged[k] = m[k]
			}
		}
	}
	addSorted(res)
	rec := map[string]string{}
	for _, kv := range kvs {
		if v := anyValueString(kv.GetValue()); v != "" {
			rec[kv.GetKey()] = v
		}
	}
	addSorted(rec)
	if len(merged) == 0 {
		return nil
	}
	return merged
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

// anyValueString renders the common OTLP value kinds as strings (non-string
// scalars included; composite kinds are skipped — bounded, not a blob dump).
func anyValueString(v *commonpb.AnyValue) string {
	switch x := v.GetValue().(type) {
	case *commonpb.AnyValue_StringValue:
		return x.StringValue
	case *commonpb.AnyValue_IntValue:
		return strconv.FormatInt(x.IntValue, 10)
	case *commonpb.AnyValue_DoubleValue:
		return strconv.FormatFloat(x.DoubleValue, 'g', -1, 64)
	case *commonpb.AnyValue_BoolValue:
		if x.BoolValue {
			return "true"
		}
		return "false"
	default:
		return ""
	}
}

func spanKind(k tracepb.Span_SpanKind) string {
	switch k {
	case tracepb.Span_SPAN_KIND_SERVER:
		return "server"
	case tracepb.Span_SPAN_KIND_CLIENT:
		return "client"
	case tracepb.Span_SPAN_KIND_PRODUCER:
		return "producer"
	case tracepb.Span_SPAN_KIND_CONSUMER:
		return "consumer"
	case tracepb.Span_SPAN_KIND_INTERNAL:
		return "internal"
	default:
		return "unspecified"
	}
}

func statusCode(s *tracepb.Status) string {
	switch s.GetCode() {
	case tracepb.Status_STATUS_CODE_OK:
		return "ok"
	case tracepb.Status_STATUS_CODE_ERROR:
		return "error"
	default:
		return "unset"
	}
}
