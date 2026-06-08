package otelstore

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/breaker"
	"github.com/imfeelingtheagi/probectl/internal/store/chmigrate"
)

// ClickHouse persists OTLP traces + logs over the ClickHouse HTTP interface
// (the pathstore/flowstore pattern: zero driver dependencies; an https URL
// is TLS in transit). Every value reaching SQL is a SERVER-BOUND parameter
// ({name:Type} + param_*) — never string-built (ARCH-002 stance).
//
// tenant_id leads both PARTITION BY and ORDER BY so tenant-scoped reads
// prune at the storage layer; the day component keeps parts bounded and the
// retention TTL cheap.

const (
	spansTable = "probectl_otel_spans"
	logsTable  = "probectl_otel_logs"
)

func createSpansDDL(table string) string {
	return `CREATE TABLE IF NOT EXISTS ` + table + ` (
  tenant_id String,
  trace_id String, span_id String, parent_span_id String,
  name String, kind LowCardinality(String), service LowCardinality(String),
  start DateTime64(6), duration_ns UInt64,
  status_code LowCardinality(String),
  attrs String
) ENGINE = MergeTree
PARTITION BY (tenant_id, toYYYYMMDD(start))
ORDER BY (tenant_id, start, service, trace_id)`
}

func createLogsDDL(table string) string {
	return `CREATE TABLE IF NOT EXISTS ` + table + ` (
  tenant_id String,
  ts DateTime64(6),
  severity_num Int32, severity_text LowCardinality(String),
  service LowCardinality(String), body String,
  trace_id String, span_id String,
  attrs String
) ENGINE = MergeTree
PARTITION BY (tenant_id, toYYYYMMDD(ts))
ORDER BY (tenant_id, ts, service)`
}

// chMigrations is the otelstore's versioned ClickHouse schema (U-046).
// Shipped versions are immutable — changes are NEW versions.
func chMigrations() []chmigrate.Migration {
	return []chmigrate.Migration{
		{Version: 1, Name: "create_otel_spans_logs", Statements: []string{
			createSpansDDL(spansTable), createLogsDDL(logsTable),
		}},
	}
}

// ClickHouse is the production Store.
type ClickHouse struct {
	base    string
	client  *http.Client
	breaker *breaker.Breaker
	// tenantScoping (TENANT-102 parity): attach the per-request custom
	// setting so the reader row policy can constrain reads at the DB.
	tenantScoping bool
}

const tenantSettingName = "SQL_probectl_tenant"

// WithTenantScoping enables per-request custom-setting tenant scoping on
// reads (pair with the reader row policy; see docs/security/tenant-isolation.md).
func (c *ClickHouse) WithTenantScoping(on bool) *ClickHouse { c.tenantScoping = on; return c }

type chExec struct{ c *ClickHouse }

func (e chExec) Exec(ctx context.Context, sql string, p chmigrate.Params) error {
	return e.c.exec(ctx, sql, chParams(p), nil)
}
func (e chExec) Query(ctx context.Context, sql string, p chmigrate.Params) ([]map[string]any, error) {
	return e.c.query(ctx, "", sql, chParams(p))
}

// NewClickHouse connects, applies the versioned schema, and (when
// retentionDays > 0) applies the delete-TTLs — idempotently.
func NewClickHouse(rawURL string, retentionDays int) (*ClickHouse, error) {
	c := &ClickHouse{base: strings.TrimRight(rawURL, "/"), client: &http.Client{Timeout: 30 * time.Second}, breaker: breaker.New(0, 0)}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if _, err := chmigrate.Apply(ctx, chExec{c}, "otelstore", chMigrations(), nil); err != nil {
		return nil, fmt.Errorf("otelstore: migrate: %w", err)
	}
	if retentionDays > 0 {
		for table, col := range map[string]string{spansTable: "start", logsTable: "ts"} {
			ttl := fmt.Sprintf("ALTER TABLE %s MODIFY TTL toDateTime(%s) + INTERVAL %d DAY DELETE", table, col, retentionDays)
			if err := c.exec(ctx, ttl, nil, nil); err != nil {
				return nil, fmt.Errorf("otelstore: apply retention TTL: %w", err)
			}
		}
	}
	return c, nil
}

// --- writes (JSONEachRow batches) ---

type chSpan struct {
	TenantID     string `json:"tenant_id"`
	TraceID      string `json:"trace_id"`
	SpanID       string `json:"span_id"`
	ParentSpanID string `json:"parent_span_id"`
	Name         string `json:"name"`
	Kind         string `json:"kind"`
	Service      string `json:"service"`
	Start        string `json:"start"`
	DurationNS   uint64 `json:"duration_ns"`
	StatusCode   string `json:"status_code"`
	Attrs        string `json:"attrs"`
}

// WriteSpans inserts one JSONEachRow batch.
func (c *ClickHouse) WriteSpans(ctx context.Context, spans []Span) error {
	if len(spans) == 0 {
		return nil
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for _, s := range spans {
		if s.TenantID == "" {
			continue // never store an unowned row
		}
		attrs, _ := json.Marshal(s.Attrs)
		row := chSpan{
			TenantID: s.TenantID, TraceID: s.TraceID, SpanID: s.SpanID, ParentSpanID: s.ParentSpanID,
			Name: s.Name, Kind: s.Kind, Service: s.Service,
			Start:      timeOrNow(s.Start).UTC().Format("2006-01-02 15:04:05.000000"),
			DurationNS: uint64(max64(int64(s.Duration), 0)), StatusCode: s.StatusCode, Attrs: string(attrs),
		}
		if err := enc.Encode(row); err != nil {
			return fmt.Errorf("otelstore: encode span: %w", err)
		}
	}
	return c.exec(ctx, "INSERT INTO "+spansTable+" FORMAT JSONEachRow", nil, &buf)
}

type chLog struct {
	TenantID     string `json:"tenant_id"`
	TS           string `json:"ts"`
	SeverityNum  int32  `json:"severity_num"`
	SeverityText string `json:"severity_text"`
	Service      string `json:"service"`
	Body         string `json:"body"`
	TraceID      string `json:"trace_id"`
	SpanID       string `json:"span_id"`
	Attrs        string `json:"attrs"`
}

// WriteLogs inserts one JSONEachRow batch.
func (c *ClickHouse) WriteLogs(ctx context.Context, recs []LogRecord) error {
	if len(recs) == 0 {
		return nil
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for _, r := range recs {
		if r.TenantID == "" {
			continue
		}
		attrs, _ := json.Marshal(r.Attrs)
		row := chLog{
			TenantID: r.TenantID, TS: timeOrNow(r.TS).UTC().Format("2006-01-02 15:04:05.000000"),
			SeverityNum: r.SeverityNum, SeverityText: r.SeverityText,
			Service: r.Service, Body: r.Body, TraceID: r.TraceID, SpanID: r.SpanID, Attrs: string(attrs),
		}
		if err := enc.Encode(row); err != nil {
			return fmt.Errorf("otelstore: encode log: %w", err)
		}
	}
	return c.exec(ctx, "INSERT INTO "+logsTable+" FORMAT JSONEachRow", nil, &buf)
}

// --- queries (server-bound parameters only) ---

// QuerySpans returns the tenant's matching spans, newest first.
func (c *ClickHouse) QuerySpans(ctx context.Context, tenant string, q SpanQuery) ([]Span, error) {
	sql := `SELECT tenant_id, trace_id, span_id, parent_span_id, name, kind, service,
  toUnixTimestamp64Micro(start) AS start_us, duration_ns, status_code, attrs
FROM ` + spansTable + `
WHERE tenant_id = {tenant:String}
  AND ({trace:String} = '' OR trace_id = {trace:String})
  AND ({svc:String} = '' OR service = {svc:String})
  AND ({since:Int64} = 0 OR start >= fromUnixTimestamp64Milli({since:Int64}))
  AND ({until:Int64} = 0 OR start <= fromUnixTimestamp64Milli({until:Int64}))
ORDER BY start DESC
LIMIT {lim:UInt32}`
	p := chParams{
		"tenant": tenant, "trace": q.TraceID, "svc": q.Service,
		"since": msOrZero(q.Since), "until": msOrZero(q.Until),
		"lim": strconv.Itoa(clampLimit(q.Limit)),
	}
	rows, err := c.queryScoped(ctx, tenant, sql, p)
	if err != nil {
		return nil, err
	}
	out := make([]Span, 0, len(rows))
	for _, r := range rows {
		out = append(out, Span{
			TenantID:     str(r["tenant_id"]),
			TraceID:      str(r["trace_id"]),
			SpanID:       str(r["span_id"]),
			ParentSpanID: str(r["parent_span_id"]),
			Name:         str(r["name"]),
			Kind:         str(r["kind"]),
			Service:      str(r["service"]),
			Start:        time.UnixMicro(i64(r["start_us"])).UTC(),
			Duration:     time.Duration(i64(r["duration_ns"])),
			StatusCode:   str(r["status_code"]),
			Attrs:        attrsOf(str(r["attrs"])),
		})
	}
	return out, nil
}

// QueryLogs returns the tenant's matching records, newest first.
func (c *ClickHouse) QueryLogs(ctx context.Context, tenant string, q LogQuery) ([]LogRecord, error) {
	sql := `SELECT tenant_id, toUnixTimestamp64Micro(ts) AS ts_us, severity_num, severity_text,
  service, body, trace_id, span_id, attrs
FROM ` + logsTable + `
WHERE tenant_id = {tenant:String}
  AND ({svc:String} = '' OR service = {svc:String})
  AND ({trace:String} = '' OR trace_id = {trace:String})
  AND ({minsev:Int32} = 0 OR severity_num >= {minsev:Int32})
  AND ({since:Int64} = 0 OR ts >= fromUnixTimestamp64Milli({since:Int64}))
  AND ({until:Int64} = 0 OR ts <= fromUnixTimestamp64Milli({until:Int64}))
ORDER BY ts DESC
LIMIT {lim:UInt32}`
	p := chParams{
		"tenant": tenant, "svc": q.Service, "trace": q.TraceID,
		"minsev": strconv.Itoa(int(q.MinSeverity)),
		"since":  msOrZero(q.Since), "until": msOrZero(q.Until),
		"lim": strconv.Itoa(clampLimit(q.Limit)),
	}
	rows, err := c.queryScoped(ctx, tenant, sql, p)
	if err != nil {
		return nil, err
	}
	out := make([]LogRecord, 0, len(rows))
	for _, r := range rows {
		out = append(out, LogRecord{
			TenantID:     str(r["tenant_id"]),
			TS:           time.UnixMicro(i64(r["ts_us"])).UTC(),
			SeverityNum:  int32(i64(r["severity_num"])),
			SeverityText: str(r["severity_text"]),
			Service:      str(r["service"]),
			Body:         str(r["body"]),
			TraceID:      str(r["trace_id"]),
			SpanID:       str(r["span_id"]),
			Attrs:        attrsOf(str(r["attrs"])),
		})
	}
	return out, nil
}

// EraseTenant deletes every signal owned by tenant (verifiable deletion,
// TENANT-008). Like flowstore, the mutation runs mutations_sync=2 so it
// returns only once the rows are gone — making the post-delete count a REAL
// verification: deleted = before-after, remaining = after (0 when clean).
func (c *ClickHouse) EraseTenant(ctx context.Context, tenant string) (deleted, remaining int, err error) {
	for _, table := range []string{spansTable, logsTable} {
		before, err := c.countTenant(ctx, table, tenant)
		if err != nil {
			return 0, -1, err
		}
		if err := c.exec(ctx, "ALTER TABLE "+table+" DELETE WHERE tenant_id = {tenant:String} SETTINGS mutations_sync = 2",
			chParams{"tenant": tenant}, nil); err != nil {
			return 0, -1, err
		}
		after, err := c.countTenant(ctx, table, tenant)
		if err != nil {
			return 0, -1, err
		}
		deleted += before - after
		remaining += after
	}
	return deleted, remaining, nil
}

// countTenant counts one tenant's rows in a table (erase verification),
// tenant-scoped like every other read.
func (c *ClickHouse) countTenant(ctx context.Context, table, tenant string) (int, error) {
	rows, err := c.queryScoped(ctx, tenant,
		"SELECT count() AS n FROM "+table+" WHERE tenant_id = {tenant:String}", chParams{"tenant": tenant})
	if err != nil {
		return 0, err
	}
	if len(rows) == 0 {
		return 0, nil
	}
	return int(i64(rows[0]["n"])), nil
}

// Close is a no-op (stateless HTTP client).
func (c *ClickHouse) Close() error { return nil }

var _ Store = (*ClickHouse)(nil)

// --- HTTP plumbing (the pathstore/flowstore shape, self-contained) ---

type chParams map[string]string

func (p chParams) qs() string {
	var b strings.Builder
	for k, v := range p {
		b.WriteString("&param_")
		b.WriteString(url.QueryEscape(k))
		b.WriteByte('=')
		b.WriteString(url.QueryEscape(v))
	}
	return b.String()
}

func (c *ClickHouse) queryScoped(ctx context.Context, tenant, sql string, p chParams) ([]map[string]any, error) {
	scope := ""
	if c.tenantScoping {
		scope = "&" + url.QueryEscape(tenantSettingName) + "=" + url.QueryEscape(tenant)
	}
	return c.query(ctx, scope, sql, p)
}

func (c *ClickHouse) query(ctx context.Context, extraQS, sql string, p chParams) ([]map[string]any, error) {
	u := c.base + "/?query=" + url.QueryEscape(sql+" FORMAT JSON") + p.qs() + extraQS
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.do(req)
	if err != nil {
		return nil, fmt.Errorf("otelstore: clickhouse request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("otelstore: clickhouse status %d: %s", resp.StatusCode, b)
	}
	var out struct {
		Data []map[string]any `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("otelstore: decode result: %w", err)
	}
	return out.Data, nil
}

func (c *ClickHouse) exec(ctx context.Context, query string, p chParams, body io.Reader) error {
	u := c.base + "/?query=" + url.QueryEscape(query) + p.qs()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, body)
	if err != nil {
		return err
	}
	resp, err := c.do(req)
	if err != nil {
		return fmt.Errorf("otelstore: clickhouse request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("otelstore: clickhouse status %d: %s", resp.StatusCode, b)
	}
	return nil
}

func (c *ClickHouse) do(req *http.Request) (*http.Response, error) {
	var resp *http.Response
	err := c.breaker.Do(func() error {
		var derr error
		resp, derr = c.client.Do(req)
		return derr
	})
	return resp, err
}

// --- result coercion helpers (ClickHouse JSON renders numbers as strings) ---

func str(v any) string {
	s, _ := v.(string)
	return s
}

func i64(v any) int64 {
	switch n := v.(type) {
	case string:
		i, _ := strconv.ParseInt(n, 10, 64)
		return i
	case float64:
		return int64(n)
	default:
		return 0
	}
}

func attrsOf(s string) map[string]string {
	if s == "" || s == "null" {
		return nil
	}
	var m map[string]string
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		return nil
	}
	return m
}

func msOrZero(t time.Time) string {
	if t.IsZero() {
		return "0"
	}
	return strconv.FormatInt(t.UnixMilli(), 10)
}

func max64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}
