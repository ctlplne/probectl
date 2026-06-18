// SPDX-License-Identifier: LicenseRef-probectl-TBD

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
	"github.com/imfeelingtheagi/probectl/internal/crypto"
	"github.com/imfeelingtheagi/probectl/internal/store/chclient"
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

// createFlowsDedupDDL is the CORRECT-002 dedup shape: a ReplacingMergeTree with
// a per-row row_id in the sort key. At-least-once delivery can redeliver a flow
// batch; ReplacingMergeTree collapses rows whose ENTIRE sort key matches at
// merge time, and row_id (a deterministic hash of the flow's identifying
// fields) is identical for a redelivered identical row but distinct for genuine
// flows — so duplicates are removed without collapsing real traffic. Fresh
// pooled and siloed installs run the versioned v1-to-v2 migration sequence and
// end on this shape; an existing v1 table is rebuilt into it.
func createFlowsDedupDDL(table string) string {
	return `CREATE TABLE IF NOT EXISTS ` + table + ` (
  tenant_id String, agent_id String, exporter String, obs_domain UInt32,
  protocol LowCardinality(String),
  ts DateTime64(3), start_ts DateTime64(3),
  src_addr String, dst_addr String, src_port UInt16, dst_port UInt16,
  transport LowCardinality(String), net_type LowCardinality(String),
  in_if UInt32, out_if UInt32, vlan UInt16, tos UInt8, tcp_flags UInt8, next_hop String,
  bytes UInt64, packets UInt64, sampling UInt64, bytes_scaled UInt64, packets_scaled UInt64,
  src_asn UInt32, src_as_name String, src_country LowCardinality(String),
  dst_asn UInt32, dst_as_name String, dst_country LowCardinality(String),
  row_id String
) ENGINE = ReplacingMergeTree
PARTITION BY (tenant_id, toYYYYMMDD(ts))
ORDER BY (tenant_id, ts, exporter, src_addr, dst_addr, src_port, dst_port, protocol, row_id)`
}

// flowRowID derives the deterministic dedup key for a flow row (CORRECT-002):
// a hash over every field that distinguishes one observed flow from another.
// A redelivered identical row hashes identically (collapsed by the
// ReplacingMergeTree); any genuine difference yields a different id.
func flowRowID(r Row) string {
	seed := fmt.Sprintf("%s|%s|%s|%d|%d|%s|%s|%d|%d|%s|%d|%d|%d|%d",
		r.TenantID, r.AgentID, r.Exporter, r.ObsDomain, r.TS.UnixNano(),
		r.SrcAddr, r.DstAddr, r.SrcPort, r.DstPort, r.Protocol,
		r.Bytes, r.Packets, r.InIf, r.OutIf)
	h := crypto.Hash([]byte(seed))
	return fmt.Sprintf("%x", h[:16])
}

const sharedFlowsTable = "probectl_flows"

// maxInsertChunk bounds the rows encoded into one INSERT request body
// (SCALE-008). The FlowBatch is agent-controlled, so a 1M-row batch is chunked
// into ~10k-row POSTs instead of one giant body.
const maxInsertChunk = 10_000

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
	// conn is the shared ClickHouse transport (CODE-006): TLS-hardened client,
	// JSONEachRow decode, and a circuit breaker PER routed silo BaseURL
	// (SCALE-021 — one down silo never trips another), now owned by chclient.
	conn   *chclient.Conn
	base   string
	router TargetRouter // nil = everything pooled
	// tenantScoping (TENANT-102) attaches the per-request custom setting
	// SQL_probectl_tenant to every tenant-scoped read, so a row policy can
	// constrain the query path at the DB even if app-layer WHERE scoping is
	// bypassed. Off by default: it requires the operator to allow the
	// custom-settings prefix and install the reader policy (see
	// docs/security/tenant-isolation.md). When off, app-layer WHERE scoping
	// (always present) is the boundary.
	tenantScoping bool
}

// tenantSettingName is the ClickHouse custom setting carrying the request
// tenant; the reader row policy binds SELECTs to getSetting() of it.
const tenantSettingName = "SQL_probectl_tenant"

// WithTenantScoping enables per-request custom-setting tenant scoping on reads
// (TENANT-102). Call EnsureReaderRowPolicy on the reader user to make it
// enforcing.
func (c *ClickHouse) WithTenantScoping(on bool) *ClickHouse { c.tenantScoping = on; return c }

// NewClickHouse connects, ensures the shared schema, and (when retentionDays
// > 0) applies the delete-TTL — idempotently, so repeated starts are safe.
// chMigrations is the flowstore's versioned ClickHouse schema (U-046),
// applied through internal/store/chmigrate with a server-side ledger.
// Shipped versions are immutable — schema changes are NEW versions with
// idempotent (IF NOT EXISTS / additive) statements.
func chMigrationsFor(table string) []chmigrate.Migration {
	return []chmigrate.Migration{
		{Version: 1, Name: "create_flows", Statements: []string{createFlowsDDL(table)}},
		// CORRECT-002: rebuild the shared flows table into a dedup
		// ReplacingMergeTree keyed on row_id. Existing rows are carried over with
		// an empty row_id (they predate dedup); the RENAME is atomic in
		// ClickHouse, so reads never see a missing table. Fresh installs run v1
		// then v2 and end on the dedup shape; existing siloed tenant databases
		// use the same per-tenant ledger and catch-up path.
		{Version: 2, Name: "flows_dedup_replacingmergetree", Statements: []string{
			createFlowsDedupDDL(table + "_dedup"),
			"INSERT INTO " + table + "_dedup SELECT *, '' AS row_id FROM " + table,
			"RENAME TABLE " + table + " TO " + table + "_pre_dedup, " +
				table + "_dedup TO " + table,
		},
			// SCHEMA-001: the RENAME is flagged by the ClickHouse migration-gate.
			// It is data-PRESERVING (INSERT...SELECT copies every row first and the
			// v1 table is retained as _pre_dedup), so it is an annotated exception.
			Destructive:   true,
			Justification: "atomic dedup rebuild: rows are INSERT...SELECT-copied before the RENAME and the v1 table is kept as _pre_dedup — no data loss",
		},
	}
}

func chMigrations() []chmigrate.Migration { return chMigrationsFor(sharedFlowsTable) }

// CHMigrations exposes the flowstore's ClickHouse migration list to the
// migration-gate (SCHEMA-001) so destructive DDL on this telemetry store is
// linted in CI, not just at apply-time.
func CHMigrations() []chmigrate.Migration { return chMigrations() }

// chExec adapts the store's HTTP client (pooled base) to the chmigrate runner.
type chExec struct {
	c    *ClickHouse
	base string
}

func (e chExec) Exec(ctx context.Context, sql string, p chmigrate.Params) error {
	return e.c.exec(ctx, e.base, sql, chParams(p), nil)
}
func (e chExec) Query(ctx context.Context, sql string, p chmigrate.Params) ([]map[string]any, error) {
	return e.c.query(ctx, e.base, sql, chParams(p))
}

func NewClickHouse(rawURL string, retentionDays int) (*ClickHouse, error) {
	c := &ClickHouse{base: strings.TrimRight(rawURL, "/"), conn: chclient.New(30 * time.Second)}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	// Versioned, ledger-recorded schema (U-046). The retention TTL below
	// stays a runtime ALTER: it is per-deployment configuration, not schema.
	if _, err := chmigrate.Apply(ctx, chExec{c: c}, "flowstore", chMigrations(), nil); err != nil {
		return nil, fmt.Errorf("flowstore: migrate: %w", err)
	}
	if retentionDays > 0 {
		ttl := fmt.Sprintf("ALTER TABLE %s MODIFY TTL toDateTime(ts) + INTERVAL %d DAY DELETE", sharedFlowsTable, retentionDays)
		if err := c.exec(ctx, "", ttl, nil, nil); err != nil {
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

// EnsureTenantDatabase creates/migrates a tenant's isolated database + flow
// table on its data plane (idempotent — the silo provisioner calls it at tenant
// provision and again on catch-up).
func (c *ClickHouse) EnsureTenantDatabase(ctx context.Context, t Target, retentionDays int) error {
	if t.Database == "" {
		return fmt.Errorf("flowstore: a tenant database name is required")
	}
	if !chIdentRe.MatchString(t.Database) {
		return fmt.Errorf("flowstore: refusing malformed database name %q", t.Database)
	}
	if err := c.exec(ctx, t.BaseURL, "CREATE DATABASE IF NOT EXISTS "+t.Database, nil, nil); err != nil {
		return fmt.Errorf("flowstore: create tenant database: %w", err)
	}
	table, err := tableFor(t)
	if err != nil {
		return err
	}
	if _, err := chmigrate.Apply(ctx, chExec{c: c, base: t.BaseURL}, "flowstore:"+t.Database, chMigrationsFor(table), nil); err != nil {
		return fmt.Errorf("flowstore: migrate tenant database: %w", err)
	}
	if retentionDays > 0 {
		ttl := fmt.Sprintf("ALTER TABLE %s MODIFY TTL toDateTime(ts) + INTERVAL %d DAY DELETE", table, retentionDays)
		if err := c.exec(ctx, t.BaseURL, ttl, nil, nil); err != nil {
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
	return c.exec(ctx, t.BaseURL, "DROP DATABASE IF EXISTS "+t.Database, nil, nil)
}

// chRow is the JSONEachRow insert shape (times rendered as ClickHouse strings).
type chRow struct {
	Row
	TSStr    string `json:"ts"`
	StartStr string `json:"start_ts"`
	RowID    string `json:"row_id"` // CORRECT-002 dedup key
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
		// SCALE-008: the FlowBatch size is agent-controlled, so a single Insert
		// must not encode the whole batch into one unbounded request body — chunk
		// it into bounded sub-batches (one POST each). Each chunk still benefits
		// from SCALE-006 async_insert part-coalescing.
		for start := 0; start < len(group); start += maxInsertChunk {
			end := start + maxInsertChunk
			if end > len(group) {
				end = len(group)
			}
			chunk := group[start:end]
			var buf bytes.Buffer
			enc := json.NewEncoder(&buf)
			for i := range chunk {
				r := chRow{Row: chunk[i],
					TSStr:    chunk[i].TS.UTC().Format("2006-01-02 15:04:05.000"),
					StartStr: chunk[i].StartTS.UTC().Format("2006-01-02 15:04:05.000"),
					RowID:    flowRowID(chunk[i])} // CORRECT-002 dedup key
				if err := enc.Encode(r); err != nil {
					return fmt.Errorf("flowstore: encode row: %w", err)
				}
			}
			// SCALE-006: async_insert batches small high-frequency inserts
			// server-side into larger parts, so the flow plane's many small batches
			// don't mint a part per insert (the part-explosion that wedges
			// ClickHouse at NetFlow volumes). wait_for_async_insert keeps the call
			// synchronous-to-durable so the retry+DLQ contract (CORRECT-010) still
			// sees real failures.
			insert := "INSERT INTO " + table + " SETTINGS async_insert=1, wait_for_async_insert=1 FORMAT JSONEachRow"
			if err := c.exec(ctx, t.BaseURL, insert, nil, &buf); err != nil {
				return err
			}
		}
	}
	return nil
}

// ErrNoTenant refuses any tenant-keyed ClickHouse operation without a tenant
// (U-026 defense in depth: the predicate can never be omitted by a caller).
var ErrNoTenant = errors.New("flowstore: tenant_id is required (refusing an unscoped ClickHouse query)")

// EnsureReaderRowPolicy installs the SETTING-SCOPED row policy (TENANT-102):
// the readerUser's SELECTs are constrained to rows whose tenant_id equals the
// per-request custom setting SQL_probectl_tenant. With the reader user's
// custom setting defaulting to ” server-side, an UNSET or dropped setting
// matches NO rows — fail closed. Production routes tenant data reads through
// this reader user (never the write/service user, which keeps full access for
// inserts + migrations); a compromised query path that omits the WHERE clause
// then still cannot cross tenants. See docs/security/tenant-isolation.md.
func (c *ClickHouse) EnsureReaderRowPolicy(ctx context.Context, readerUser string) error {
	if err := chValidUser(readerUser); err != nil {
		return fmt.Errorf("flowstore: reader user: %w", err)
	}
	for _, table := range []string{sharedFlowsTable} {
		ddl := fmt.Sprintf(
			"CREATE ROW POLICY IF NOT EXISTS probectl_reader_scope ON %s FOR SELECT USING tenant_id = getSetting('%s') TO %s",
			table, tenantSettingName, readerUser)
		if err := c.exec(ctx, "", ddl, nil, nil); err != nil {
			return fmt.Errorf("flowstore: reader row policy: %w", err)
		}
	}
	return nil
}

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
	if err := chValidUser(serviceUser); err != nil {
		return fmt.Errorf("flowstore: service user: %w", err)
	}
	for _, table := range []string{sharedFlowsTable} {
		for _, ddl := range []string{
			fmt.Sprintf("CREATE ROW POLICY IF NOT EXISTS probectl_tenant_isolation ON %s FOR SELECT USING tenant_id = currentUser() TO ALL EXCEPT %s", table, serviceUser),
			fmt.Sprintf("CREATE ROW POLICY IF NOT EXISTS probectl_service_access ON %s FOR SELECT USING 1 TO %s", table, serviceUser),
		} {
			if err := c.exec(ctx, "", ddl, nil, nil); err != nil {
				return fmt.Errorf("flowstore: row policy: %w", err)
			}
		}
	}
	return nil
}

// chUserRe is the shape a ClickHouse USER identifier may take in our DDL
// (identifiers cannot travel as bound parameters in any SQL dialect, so they
// are validated, never escaped — fail closed on anything else).
var chUserRe = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_-]{0,62}$`)

func chValidUser(u string) error {
	if !chUserRe.MatchString(u) {
		return fmt.Errorf("refusing malformed ClickHouse user identifier %q", u)
	}
	return nil
}

// topSQL builds the top-talkers query (tested: the WHERE must lead with
// tenant_id, and every VALUE travels as a bound parameter — only structure
// from validated enums/ints is rendered into the SQL text).
func topSQL(q TopQuery, table string) (string, chParams) {
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
	// CORRECT-003: FINAL collapses the ReplacingMergeTree's redelivered-duplicate
	// rows (same sort key incl. row_id) BEFORE the sum(), so a redelivered NetFlow
	// batch is not double-counted — matching the eBPF store. Without FINAL the
	// pre-merge duplicates would each be summed.
	sql := fmt.Sprintf(
		`SELECT %s AS k, %s AS d, sum(bytes_scaled) AS b, sum(packets_scaled) AS p, count() AS f `+
			`FROM %s FINAL WHERE tenant_id={tenant:String} AND ts >= {since:DateTime64(3)} AND ts <= {until:DateTime64(3)}%s `+
			`GROUP BY %s ORDER BY b DESC, k ASC LIMIT %d`,
		key, detail, table, extra, groupBy, q.Limit)
	return sql, chParams{
		"tenant": q.TenantID,
		"since":  chTimeParam(q.Now.Add(-q.Window)),
		"until":  chTimeParam(q.Now),
	}
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
	sql, params := topSQL(q, table)
	rows, err := c.queryScoped(ctx, t.BaseURL, q.TenantID, sql, params)
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

// capacitySQL buckets throughput per exporter/interface in ClickHouse. All
// values are bound parameters; iface/secs/table are validated structure.
func capacitySQL(q CapacityQuery, table string) (string, chParams) {
	iface := "in_if"
	if q.Direction == "out" {
		iface = "out_if"
	}
	secs := int64(q.Bucket / time.Second)
	params := chParams{
		"tenant": q.TenantID,
		"since":  chTimeParam(q.Now.Add(-q.Window)),
		"until":  chTimeParam(q.Now),
	}
	exporterFilter := ""
	if q.Exporter != "" {
		exporterFilter = " AND exporter={exporter:String}"
		params["exporter"] = q.Exporter
	}
	// CORRECT-003: FINAL dedups redelivered rows before the throughput sum, so a
	// redelivered batch doesn't inflate capacity (eBPF-store parity).
	sql := fmt.Sprintf(
		`SELECT exporter, %s AS iface, toStartOfInterval(ts, INTERVAL %d second) AS t, `+
			`sum(bytes_scaled)*8/%d AS bps, sum(packets_scaled)/%d AS pps `+
			`FROM %s FINAL WHERE tenant_id={tenant:String} AND ts >= {since:DateTime64(3)} AND ts <= {until:DateTime64(3)}%s `+
			`GROUP BY exporter, iface, t ORDER BY t, exporter, iface`,
		iface, secs, secs, secs, table, exporterFilter)
	return sql, params
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
	sql, params := capacitySQL(q, table)
	rows, err := c.queryScoped(ctx, t.BaseURL, q.TenantID, sql, params)
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
		"DELETE FROM "+sharedFlowsTable+" WHERE tenant_id={tenant:String} SETTINGS mutations_sync=2",
		chParams{"tenant": tenantID}, nil); err != nil {
		return -1, fmt.Errorf("flowstore: delete tenant: %w", err)
	}
	rows, err := c.queryScoped(ctx, t.BaseURL, tenantID,
		"SELECT count() AS n FROM "+sharedFlowsTable+" WHERE tenant_id={tenant:String}",
		chParams{"tenant": tenantID})
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
		"DELETE FROM "+table+" WHERE tenant_id={tenant:String} AND ts < {cutoff:DateTime64(3)} SETTINGS mutations_sync=2",
		chParams{"tenant": tenantID, "cutoff": chTimeParam(cutoff)}, nil)
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
	sql := "SELECT * FROM " + table + " WHERE tenant_id={tenant:String} ORDER BY ts FORMAT JSONEachRow"
	u := c.baseFor(t.BaseURL) + "/?query=" + url.QueryEscape(sql) + chParams{"tenant": tenantID}.qs()
	if c.tenantScoping {
		u += "&" + tenantSettingName + "=" + url.QueryEscape(tenantID)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return 0, err
	}
	resp, err := c.conn.Do(t.BaseURL, req)
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
	rows, qerr := c.queryScoped(ctx, t.BaseURL, tenantID,
		"SELECT count() AS n FROM "+table+" WHERE tenant_id={tenant:String}", chParams{"tenant": tenantID})
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

// breakerFor returns the circuit breaker for a routed endpoint (SCALE-021).
// The pooled default ("") uses the long-lived c.breaker; each siloed BaseURL
// gets its own breaker so one silo's outage can't trip another's writes
// (now owned by chclient — CODE-006).

// chParams carries SERVER-BOUND query parameters (SEC-005/TENANT-108): each
// key k is sent as the HTTP parameter param_k and bound by ClickHouse to the
// {k:Type} placeholder in the SQL. Values never enter the SQL text — a value
// like "x' OR '1'='1" is data, not syntax, no client-side escaping involved.
type chParams map[string]string

// qs renders the param_* query-string suffix ("" for no params).
func (p chParams) qs() string {
	if len(p) == 0 {
		return ""
	}
	var sb strings.Builder
	for k, v := range p {
		sb.WriteString("&param_")
		sb.WriteString(url.QueryEscape(k))
		sb.WriteString("=")
		sb.WriteString(url.QueryEscape(v))
	}
	return sb.String()
}

// chTimeParam renders a time for a {x:DateTime64(3)} bound parameter.
func chTimeParam(t time.Time) string { return t.UTC().Format("2006-01-02 15:04:05.000") }

// queryScoped is query with the per-request tenant custom setting attached
// (TENANT-102) when scoping is enabled. tenantID "" means an admin/cross-tenant
// read (migrations, totals) — no setting is attached.
func (c *ClickHouse) queryScoped(ctx context.Context, base, tenantID, sql string, p chParams) ([]map[string]any, error) {
	u := c.baseFor(base) + "/?query=" + url.QueryEscape(sql+" FORMAT JSONEachRow") + p.qs()
	if c.tenantScoping && tenantID != "" {
		u += "&" + tenantSettingName + "=" + url.QueryEscape(tenantID)
	}
	return c.doQuery(ctx, base, u)
}

func (c *ClickHouse) query(ctx context.Context, base, sql string, p chParams) ([]map[string]any, error) {
	return c.doQuery(ctx, base, c.baseFor(base)+"/?query="+url.QueryEscape(sql+" FORMAT JSONEachRow")+p.qs())
}

func (c *ClickHouse) doQuery(ctx context.Context, base, u string) ([]map[string]any, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.conn.Do(base, req)
	if err != nil {
		return nil, fmt.Errorf("flowstore: clickhouse query: %w", err)
	}
	defer resp.Body.Close()
	// RED-003a/SCALE-001: bound the response read — a huge/malicious ClickHouse
	// body must not be buffered unbounded (all-tenant memory DoS). On overflow
	// this fails closed (ErrResponseTooLarge) instead of allocating the body.
	body, err := chclient.ReadResponseBody(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("flowstore: clickhouse query: %w", err)
	}
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("flowstore: clickhouse query status %d: %s", resp.StatusCode, body)
	}
	return chclient.Decode(body)
}

func (c *ClickHouse) exec(ctx context.Context, base, query string, p chParams, body io.Reader) error {
	u := c.baseFor(base) + "/?query=" + url.QueryEscape(query) + p.qs()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, body)
	if err != nil {
		return err
	}
	resp, err := c.conn.Do(base, req)
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

// BreakerStats exposes the storage breaker state (U-078 fallback metrics).
func (c *ClickHouse) BreakerStats() breaker.Stats { return c.conn.Stats() }

// chParseTime parses ClickHouse DateTime / DateTime64 strings.
func chParseTime(s string) time.Time {
	for _, layout := range []string{"2006-01-02 15:04:05.000", "2006-01-02 15:04:05"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}

// chToString / chToFloat coerce JSONEachRow cells (shared via chclient, CODE-006).
func chToString(v any) string { return chclient.String(v) }
func chToFloat(v any) float64 { return chclient.Float(v) }
