package flowstore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/breaker"
	"github.com/imfeelingtheagi/probectl/internal/store/chmigrate"
)

// tenant_id leads both the partition and the ORDER BY so tenant-scoped reads
// prune at the storage layer (CLAUDE.md §4, §6); the day component bounds part
// sizes at NetFlow volumes and makes the retention TTL cheap to apply. The
// LowCardinality columns keep the high-volume dictionary small.
func createFlowsDDL(table string) string {
	return `CREATE TABLE IF NOT EXISTS ` + table + ` (
  tenant_id String, agent_id String, exporter String, obs_domain UInt32,
  protocol LowCardinality(String),
  ts DateTime64(3), start_ts DateTime64(3),
  src_addr String, dst_addr String, src_port UInt16, dst_port UInt16,
  transport LowCardinality(String), net_type LowCardinality(String),
  in_if UInt32, out_if UInt32, vlan UInt16, tos UInt8, tcp_flags UInt8, next_hop String,
  bytes UInt64, packets UInt64, sampling UInt64, bytes_scaled UInt64, packets_scaled UInt64,
  src_asn UInt32, src_as_name String, src_country LowCardinality(String),
  dst_asn UInt32, dst_as_name String, dst_country LowCardinality(String)
) ENGINE = MergeTree
PARTITION BY (tenant_id, toYYYYMMDD(ts))
ORDER BY (tenant_id, ts, exporter, src_addr, dst_addr)`
}

const sharedFlowsTable = "probectl_flows"

// Target is where one tenant's flows live (S-T2 siloed/hybrid isolation).
// The zero value is the shared (pooled) deployment store. Database routes to
// a per-tenant ClickHouse database; BaseURL pins a residency data plane.
type Target struct {
	BaseURL  string
	Database string
}

// TargetRouter resolves a tenant's flow-store target. It must FAIL CLOSED: a
// routing error fails the operation rather than silently landing a siloed
// tenant's rows in the pooled table (the S-T2 watch-out).
type TargetRouter func(tenantID string) (Target, error)

var chIdentRe = regexp.MustCompile(`^[a-z_][a-z0-9_]{0,62}$`)

// tableFor renders the routed table reference, refusing malformed database
// names (defense in depth — names derive from UUIDs, never user input).
func tableFor(t Target) (string, error) {
	if t.Database == "" {
		return sharedFlowsTable, nil
	}
	if !chIdentRe.MatchString(t.Database) {
		return "", fmt.Errorf("flowstore: refusing malformed database name %q", t.Database)
	}
	return t.Database + "." + sharedFlowsTable, nil
}

// ClickHouse persists flows over the ClickHouse HTTP interface (pathstore
// pattern: zero driver dependencies; https URL = TLS in transit).
type ClickHouse struct {
	breaker *breaker.Breaker
	base    string
	client  *http.Client
	router  TargetRouter // nil = everything pooled
}

// NewClickHouse connects, ensures the shared schema, and (when retentionDays
// > 0) applies the delete-TTL — idempotently, so repeated starts are safe.
// chMigrations is the flowstore's versioned ClickHouse schema (U-046),
// applied through internal/store/chmigrate with a server-side ledger.
// Shipped versions are immutable — schema changes are NEW versions with
// idempotent (IF NOT EXISTS / additive) statements.
func chMigrations() []chmigrate.Migration {
	return []chmigrate.Migration{
		{Version: 1, Name: "create_flows", Statements: []string{createFlowsDDL(sharedFlowsTable)}},
	}
}

// chExec adapts the store's HTTP client (pooled base) to the chmigrate runner.
type chExec struct{ c *ClickHouse }

func (e chExec) Exec(ctx context.Context, sql string) error { return e.c.exec(ctx, "", sql, nil) }
func (e chExec) Query(ctx context.Context, sql string) ([]map[string]any, error) {
	return e.c.query(ctx, "", sql)
}

func NewClickHouse(rawURL string, retentionDays int) (*ClickHouse, error) {
	c := &ClickHouse{base: strings.TrimRight(rawURL, "/"), client: &http.Client{Timeout: 30 * time.Second}, breaker: breaker.New(0, 0)}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	// Versioned, ledger-recorded schema (U-046). The retention TTL below
	// stays a runtime ALTER: it is per-deployment configuration, not schema.
	if _, err := chmigrate.Apply(ctx, chExec{c}, "flowstore", chMigrations(), nil); err != nil {
		return nil, fmt.Errorf("flowstore: migrate: %w", err)
	}
	if retentionDays > 0 {
		ttl := fmt.Sprintf("ALTER TABLE %s MODIFY TTL toDateTime(ts) + INTERVAL %d DAY DELETE", sharedFlowsTable, retentionDays)
		if err := c.exec(ctx, "", ttl, nil); err != nil {
			return nil, fmt.Errorf("flowstore: apply retention TTL: %w", err)
		}
	}
	return c, nil
}

// WithRouter installs the isolation router (S-T2; the main.go attach seam).
// nil keeps everything pooled.
func (c *ClickHouse) WithRouter(r TargetRouter) *ClickHouse {
	c.router = r
	return c
}

// route resolves one tenant's target (pooled when no router is installed).
func (c *ClickHouse) route(tenantID string) (Target, error) {
	if c.router == nil {
		return Target{}, nil
	}
	return c.router(tenantID)
}

// EnsureTenantDatabase creates a tenant's isolated database + flow table on
// its data plane (idempotent — the silo provisioner calls it at tenant
// provision and again on catch-up).
func (c *ClickHouse) EnsureTenantDatabase(ctx context.Context, t Target, retentionDays int) error {
	if t.Database == "" {
		return fmt.Errorf("flowstore: a tenant database name is required")
	}
	if !chIdentRe.MatchString(t.Database) {
		return fmt.Errorf("flowstore: refusing malformed database name %q", t.Database)
	}
	if err := c.exec(ctx, t.BaseURL, "CREATE DATABASE IF NOT EXISTS "+t.Database, nil); err != nil {
		return fmt.Errorf("flowstore: create tenant database: %w", err)
	}
	table, err := tableFor(t)
	if err != nil {
		return err
	}
	if err := c.exec(ctx, t.BaseURL, createFlowsDDL(table), nil); err != nil {
		return fmt.Errorf("flowstore: create tenant table: %w", err)
	}
	if retentionDays > 0 {
		ttl := fmt.Sprintf("ALTER TABLE %s MODIFY TTL toDateTime(ts) + INTERVAL %d DAY DELETE", table, retentionDays)
		if err := c.exec(ctx, t.BaseURL, ttl, nil); err != nil {
			return fmt.Errorf("flowstore: tenant retention TTL: %w", err)
		}
	}
	return nil
}

// DropTenantDatabase removes a siloed tenant's database (offboard teardown).
// Idempotent: dropping an absent database succeeds.
func (c *ClickHouse) DropTenantDatabase(ctx context.Context, t Target) error {
	if t.Database == "" || !chIdentRe.MatchString(t.Database) {
		return fmt.Errorf("flowstore: refusing to drop malformed database name %q", t.Database)
	}
	return c.exec(ctx, t.BaseURL, "DROP DATABASE IF EXISTS "+t.Database, nil)
}

// chRow is the JSONEachRow insert shape (times rendered as ClickHouse strings).
type chRow struct {
	Row
	TSStr    string `json:"ts"`
	StartStr string `json:"start_ts"`
}

// Insert streams rows as JSONEachRow batches — one request per routed target
// per flush (pooled deployments keep exactly the old single-request path).
// Routing failures fail the batch (fail closed) rather than misfiling rows.
func (c *ClickHouse) Insert(ctx context.Context, rows []Row) error {
	if len(rows) == 0 {
		return nil
	}
	groups := map[Target][]Row{}
	for i := range rows {
		t, err := c.route(rows[i].TenantID)
		if err != nil {
			return fmt.Errorf("flowstore: route tenant %s: %w", rows[i].TenantID, err)
		}
		groups[t] = append(groups[t], rows[i])
	}
	for t, group := range groups {
		table, err := tableFor(t)
		if err != nil {
			return err
		}
		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		for i := range group {
			r := chRow{Row: group[i],
				TSStr:    group[i].TS.UTC().Format("2006-01-02 15:04:05.000"),
				StartStr: group[i].StartTS.UTC().Format("2006-01-02 15:04:05.000")}
			if err := enc.Encode(r); err != nil {
				return fmt.Errorf("flowstore: encode row: %w", err)
			}
		}
		if err := c.exec(ctx, t.BaseURL, "INSERT INTO "+table+" FORMAT JSONEachRow", &buf); err != nil {
			return err
		}
	}
	return nil
}

// ErrNoTenant refuses any tenant-keyed ClickHouse operation without a tenant
// (U-026 defense in depth: the predicate can never be omitted by a caller).
var ErrNoTenant = errors.New("flowstore: tenant_id is required (refusing an unscoped ClickHouse query)")

// EnsureRowPolicies installs DB-LEVEL tenancy on the shared tables (U-026):
// per-tenant ClickHouse users (named exactly the tenant id, per the operator
// convention in docs/isolation.md) are row-filtered to tenant_id =
// currentUser(), while serviceUser (probectl's own account) keeps full
// access via a permissive policy. Direct CH access with a tenant credential
// can then never cross tenants, independent of this codebase.
func (c *ClickHouse) EnsureRowPolicies(ctx context.Context, serviceUser string) error {
	if serviceUser == "" {
		serviceUser = "default"
	}
	for _, table := range []string{sharedFlowsTable} {
		for _, ddl := range []string{
			fmt.Sprintf("CREATE ROW POLICY IF NOT EXISTS probectl_tenant_isolation ON %s FOR SELECT USING tenant_id = currentUser() TO ALL EXCEPT %s", table, serviceUser),
			fmt.Sprintf("CREATE ROW POLICY IF NOT EXISTS probectl_service_access ON %s FOR SELECT USING 1 TO %s", table, serviceUser),
		} {
			if err := c.exec(ctx, "", ddl, nil); err != nil {
				return fmt.Errorf("flowstore: row policy: %w", err)
			}
		}
	}
	return nil
}

// topSQL builds the top-talkers query (exported via a test for the tenant
// guard: the WHERE must lead with tenant_id).
func topSQL(q TopQuery, table string) string {
	var key, detail, extra string
	switch q.By {
	case BySrc:
		key, detail = "src_addr", "''"
	case ByDst:
		key, detail = "dst_addr", "''"
	case ByPair:
		key, detail = "src_addr", "dst_addr"
	case BySrcASN:
		key, detail, extra = "toString(src_asn)", "any(src_as_name)", " AND src_asn != 0"
	case ByDstASN:
		key, detail, extra = "toString(dst_asn)", "any(dst_as_name)", " AND dst_asn != 0"
	}
	groupBy := "k"
	if q.By == ByPair {
		groupBy = "k, d"
	}
	return fmt.Sprintf(
		`SELECT %s AS k, %s AS d, sum(bytes_scaled) AS b, sum(packets_scaled) AS p, count() AS f `+
			`FROM %s WHERE tenant_id=%s AND ts >= %s AND ts <= %s%s `+
			`GROUP BY %s ORDER BY b DESC, k ASC LIMIT %d`,
		key, detail, table, chStr(q.TenantID), chTime(q.Now.Add(-q.Window)), chTime(q.Now), extra, groupBy, q.Limit)
}

// TopTalkers runs the aggregation in ClickHouse, on the tenant's routed store.
func (c *ClickHouse) TopTalkers(ctx context.Context, q TopQuery) ([]TopRow, error) {
	if q.TenantID == "" {
		return nil, ErrNoTenant
	}
	if err := q.normalize(); err != nil {
		return nil, err
	}
	t, err := c.route(q.TenantID)
	if err != nil {
		return nil, err
	}
	table, err := tableFor(t)
	if err != nil {
		return nil, err
	}
	rows, err := c.query(ctx, t.BaseURL, topSQL(q, table))
	if err != nil {
		return nil, err
	}
	out := make([]TopRow, 0, len(rows))
	for _, r := range rows {
		out = append(out, TopRow{
			Key:     chToString(r["k"]),
			Detail:  chToString(r["d"]),
			Bytes:   uint64(chToFloat(r["b"])),
			Packets: uint64(chToFloat(r["p"])),
			Flows:   uint64(chToFloat(r["f"])),
		})
	}
	return out, nil
}

// capacitySQL buckets throughput per exporter/interface in ClickHouse.
func capacitySQL(q CapacityQuery, table string) string {
	iface := "in_if"
	if q.Direction == "out" {
		iface = "out_if"
	}
	secs := int64(q.Bucket / time.Second)
	exporterFilter := ""
	if q.Exporter != "" {
		exporterFilter = " AND exporter=" + chStr(q.Exporter)
	}
	return fmt.Sprintf(
		`SELECT exporter, %s AS iface, toStartOfInterval(ts, INTERVAL %d second) AS t, `+
			`sum(bytes_scaled)*8/%d AS bps, sum(packets_scaled)/%d AS pps `+
			`FROM %s WHERE tenant_id=%s AND ts >= %s AND ts <= %s%s `+
			`GROUP BY exporter, iface, t ORDER BY t, exporter, iface`,
		iface, secs, secs, secs, table, chStr(q.TenantID), chTime(q.Now.Add(-q.Window)), chTime(q.Now), exporterFilter)
}

// Capacity runs the bucket aggregation in ClickHouse, on the routed store.
func (c *ClickHouse) Capacity(ctx context.Context, q CapacityQuery) ([]CapacityPoint, error) {
	if q.TenantID == "" {
		return nil, ErrNoTenant
	}
	if err := q.normalize(); err != nil {
		return nil, err
	}
	t, err := c.route(q.TenantID)
	if err != nil {
		return nil, err
	}
	table, err := tableFor(t)
	if err != nil {
		return nil, err
	}
	rows, err := c.query(ctx, t.BaseURL, capacitySQL(q, table))
	if err != nil {
		return nil, err
	}
	out := make([]CapacityPoint, 0, len(rows))
	for _, r := range rows {
		out = append(out, CapacityPoint{
			TS:       chParseTime(chToString(r["t"])),
			Exporter: chToString(r["exporter"]),
			Iface:    uint32(chToFloat(r["iface"])),
			Bps:      chToFloat(r["bps"]),
			Pps:      chToFloat(r["pps"]),
		})
	}
	return out, nil
}

// DeleteTenant removes EVERY flow of one tenant. A siloed tenant's database
// is DROPPED (the whole container); pooled tenants get a synchronous
// lightweight-delete mutation (mutations_sync=2 — the call returns only when
// the rows are gone, so the returned remaining-count is a real verification).
func (c *ClickHouse) DeleteTenant(ctx context.Context, tenantID string) (int64, error) {
	if tenantID == "" {
		return 0, ErrNoTenant
	}
	t, err := c.route(tenantID)
	if err != nil {
		return -1, err
	}
	if t.Database != "" { // siloed/hybrid: drop the per-tenant database
		if err := c.DropTenantDatabase(ctx, t); err != nil {
			return -1, err
		}
		return 0, nil
	}
	if err := c.exec(ctx, t.BaseURL,
		"DELETE FROM "+sharedFlowsTable+" WHERE tenant_id="+chStr(tenantID)+" SETTINGS mutations_sync=2", nil); err != nil {
		return -1, fmt.Errorf("flowstore: delete tenant: %w", err)
	}
	rows, err := c.query(ctx, t.BaseURL,
		"SELECT count() AS n FROM "+sharedFlowsTable+" WHERE tenant_id="+chStr(tenantID))
	if err != nil {
		return -1, err
	}
	var remaining int64
	if len(rows) > 0 {
		remaining = int64(chToFloat(rows[0]["n"]))
	}
	return remaining, nil
}

// DeleteTenantBefore removes one tenant's flows older than cutoff (S-T5
// per-tenant retention), on the tenant's routed store.
func (c *ClickHouse) DeleteTenantBefore(ctx context.Context, tenantID string, cutoff time.Time) error {
	if tenantID == "" {
		return ErrNoTenant
	}
	t, err := c.route(tenantID)
	if err != nil {
		return err
	}
	table, err := tableFor(t)
	if err != nil {
		return err
	}
	return c.exec(ctx, t.BaseURL,
		"DELETE FROM "+table+" WHERE tenant_id="+chStr(tenantID)+" AND ts < "+chTime(cutoff)+" SETTINGS mutations_sync=2", nil)
}

// ExportTenant streams one tenant's flows as JSON Lines into w, straight from
// the ClickHouse HTTP response (no buffering — exports can be large).
func (c *ClickHouse) ExportTenant(ctx context.Context, tenantID string, w io.Writer) (int64, error) {
	if tenantID == "" {
		return 0, ErrNoTenant
	}
	t, err := c.route(tenantID)
	if err != nil {
		return 0, err
	}
	table, err := tableFor(t)
	if err != nil {
		return 0, err
	}
	sql := "SELECT * FROM " + table + " WHERE tenant_id=" + chStr(tenantID) + " ORDER BY ts FORMAT JSONEachRow"
	u := c.baseFor(t.BaseURL) + "/?query=" + url.QueryEscape(sql)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return 0, err
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("flowstore: export: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return 0, fmt.Errorf("flowstore: export status %d: %s", resp.StatusCode, b)
	}
	n, err := io.Copy(&lineCounter{w: w}, resp.Body)
	_ = n
	if err != nil {
		return 0, err
	}
	// Count exported lines for the manifest.
	rows, qerr := c.query(ctx, t.BaseURL, "SELECT count() AS n FROM "+table+" WHERE tenant_id="+chStr(tenantID))
	if qerr != nil || len(rows) == 0 {
		return -1, nil // streamed fine; count unavailable
	}
	return int64(chToFloat(rows[0]["n"])), nil
}

// lineCounter passes bytes through (kept simple; counting via the follow-up
// count query keeps the stream zero-copy).
type lineCounter struct{ w io.Writer }

func (l *lineCounter) Write(p []byte) (int, error) { return l.w.Write(p) }

// Anomalies fetches the capacity series and applies the shared detector, so
// ClickHouse and Memory flag identically.
func (c *ClickHouse) Anomalies(ctx context.Context, q AnomalyQuery) ([]Anomaly, error) {
	if err := q.normalize(); err != nil {
		return nil, err
	}
	series, err := c.Capacity(ctx, q.capacityQuery())
	if err != nil {
		return nil, err
	}
	return detectAnomalies(series, q), nil
}

// Close is a no-op (the HTTP client needs no teardown).
func (c *ClickHouse) Close() error { return nil }

// --- HTTP plumbing (pathstore pattern) ---------------------------------------

// baseFor picks the data-plane endpoint ("" = the deployment default).
func (c *ClickHouse) baseFor(base string) string {
	if base == "" {
		return c.base
	}
	return strings.TrimRight(base, "/")
}

func (c *ClickHouse) query(ctx context.Context, base, sql string) ([]map[string]any, error) {
	u := c.baseFor(base) + "/?query=" + url.QueryEscape(sql+" FORMAT JSONEachRow")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("flowstore: clickhouse query: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("flowstore: clickhouse query status %d: %s", resp.StatusCode, body)
	}
	var rows []map[string]any
	for _, line := range bytes.Split(body, []byte("\n")) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var row map[string]any
		if err := json.Unmarshal(line, &row); err != nil {
			return nil, fmt.Errorf("flowstore: decode row: %w", err)
		}
		rows = append(rows, row)
	}
	return rows, nil
}

func (c *ClickHouse) exec(ctx context.Context, base, query string, body io.Reader) error {
	u := c.baseFor(base) + "/?query=" + url.QueryEscape(query)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, body)
	if err != nil {
		return err
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("flowstore: clickhouse request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("flowstore: clickhouse status %d: %s", resp.StatusCode, b)
	}
	return nil
}

// chDo issues the request through the circuit breaker (U-078): a transport
// failure (upstream down) counts toward tripping; the breaker short-circuits
// while open instead of stacking connect timeouts.
func chDo(b *breaker.Breaker, client *http.Client, req *http.Request) (*http.Response, error) {
	var resp *http.Response
	err := b.Do(func() error {
		r, e := client.Do(req)
		if e != nil {
			return e
		}
		resp = r
		return nil
	})
	return resp, err
}

// BreakerStats exposes the storage breaker state (U-078 fallback metrics).
func (c *ClickHouse) BreakerStats() breaker.Stats { return c.breaker.Stats() }

// chStr renders a ClickHouse string literal with the necessary escaping.
func chStr(s string) string {
	return "'" + strings.NewReplacer(`\`, `\\`, `'`, `\'`).Replace(s) + "'"
}

// chTime renders an absolute DateTime64 literal.
func chTime(t time.Time) string {
	return "toDateTime64(" + chStr(t.UTC().Format("2006-01-02 15:04:05.000")) + ", 3)"
}

// chParseTime parses ClickHouse DateTime / DateTime64 strings.
func chParseTime(s string) time.Time {
	for _, layout := range []string{"2006-01-02 15:04:05.000", "2006-01-02 15:04:05"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}

func chToString(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func chToFloat(v any) float64 {
	switch n := v.(type) {
	case float64:
		return n
	case string:
		var f float64
		_, _ = fmt.Sscanf(n, "%g", &f)
		return f
	}
	return 0
}
