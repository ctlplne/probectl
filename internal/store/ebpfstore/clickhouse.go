// SPDX-License-Identifier: LicenseRef-probectl-TBD

package ebpfstore

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/store/chclient"
	"github.com/imfeelingtheagi/probectl/internal/store/chmigrate"
)

const edgesTable = "probectl_ebpf_edges"

// tenantSettingName is the ClickHouse custom setting carrying the request
// tenant; the setting-scoped reader row policy binds SELECTs to getSetting()
// of it (TENANT-004 parity with flowstore/otelstore).
const tenantSettingName = "SQL_probectl_tenant"

// ClickHouse persists eBPF aggregates over the ClickHouse HTTP interface. The
// transport (TLS-hardened client, circuit breaker, JSONEachRow decode) is the
// shared chclient (CODE-006); this type owns only the eBPF schema + queries.
type ClickHouse struct {
	base string
	conn *chclient.Conn
	// tenantScoping (TENANT-004): attach the per-request tenant custom setting
	// to tenant-scoped reads so the reader row policy can constrain the query
	// path at the DB even if app-layer WHERE scoping is bypassed. Off by
	// default; defaulted on by the multi-tenant/regulated profile.
	tenantScoping bool
}

// WithTenantScoping enables per-request custom-setting tenant scoping on reads
// (pair with EnsureReaderRowPolicy on the reader user).
func (c *ClickHouse) WithTenantScoping(on bool) *ClickHouse { c.tenantScoping = on; return c }

// edgesDDL is tenant-led (partition + ORDER BY) and a ReplacingMergeTree so a
// redelivered identical aggregate collapses (CORRECT-002 discipline). The day
// partition keeps the per-tenant delete-TTL cheap.
func edgesDDL() string {
	return `CREATE TABLE IF NOT EXISTS ` + edgesTable + ` (
  tenant_id String, agent_id String, window_start DateTime64(3),
  src_workload String, dst_workload String, dst_port UInt16,
  l7_protocol LowCardinality(String),
  bytes UInt64, packets UInt64, connections UInt64
) ENGINE = ReplacingMergeTree
PARTITION BY (tenant_id, toYYYYMMDD(window_start))
ORDER BY (tenant_id, window_start, src_workload, dst_workload, dst_port, l7_protocol)`
}

func chMigrations() []chmigrate.Migration {
	return []chmigrate.Migration{
		{Version: 1, Name: "create_ebpf_edges", Statements: []string{edgesDDL()}},
	}
}

type chExec struct{ c *ClickHouse }

func (e chExec) Exec(ctx context.Context, sql string, _ chmigrate.Params) error {
	return e.c.exec(ctx, sql, nil)
}
func (e chExec) Query(ctx context.Context, sql string, _ chmigrate.Params) ([]map[string]any, error) {
	return e.c.query(ctx, sql)
}

// NewClickHouse connects, applies the versioned schema, and (retentionDays>0)
// sets the delete-TTL.
func NewClickHouse(rawURL string, retentionDays int) (*ClickHouse, error) {
	c := &ClickHouse{
		base: strings.TrimRight(rawURL, "/"),
		conn: chclient.New(30 * time.Second),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if _, err := chmigrate.Apply(ctx, chExec{c}, "ebpfstore", chMigrations(), nil); err != nil {
		return nil, fmt.Errorf("ebpfstore: migrate: %w", err)
	}
	if retentionDays > 0 {
		ttl := fmt.Sprintf("ALTER TABLE %s MODIFY TTL toDateTime(window_start) + INTERVAL %d DAY DELETE", edgesTable, retentionDays)
		if err := c.exec(ctx, ttl, nil); err != nil {
			return nil, fmt.Errorf("ebpfstore: apply retention TTL: %w", err)
		}
	}
	return c, nil
}

type chEdge struct {
	Edge
	WindowStr string `json:"window_start"`
}

// Insert streams the batch as JSONEachRow.
func (c *ClickHouse) Insert(ctx context.Context, edges []Edge) error {
	if len(edges) == 0 {
		return nil
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for _, e := range edges {
		if e.TenantID == "" {
			continue // unscoped rows are dropped fail-closed
		}
		if err := enc.Encode(chEdge{Edge: e, WindowStr: e.WindowStart.UTC().Format("2006-01-02 15:04:05.000")}); err != nil {
			return fmt.Errorf("ebpfstore: encode: %w", err)
		}
	}
	// SCALE-006: async_insert coalesces the many small eBPF batches server-side
	// instead of minting a part each; wait_for_async_insert keeps it durable.
	return c.exec(ctx, "INSERT INTO "+edgesTable+" SETTINGS async_insert=1, wait_for_async_insert=1 FORMAT JSONEachRow", &buf)
}

// TopEdges returns the tenant's heaviest edges in the window (bytes-desc),
// server-bound tenant parameter (never string-concatenated).
func (c *ClickHouse) TopEdges(ctx context.Context, tenantID string, q EdgeQuery) ([]Edge, error) {
	if tenantID == "" {
		return nil, ErrNoTenant
	}
	where := "tenant_id={tenant:String}"
	params := url.Values{"param_tenant": {tenantID}}
	if !q.Since.IsZero() {
		where += " AND window_start>={since:DateTime64(3)}"
		params.Set("param_since", q.Since.UTC().Format("2006-01-02 15:04:05.000"))
	}
	if !q.Until.IsZero() {
		where += " AND window_start<={until:DateTime64(3)}"
		params.Set("param_until", q.Until.UTC().Format("2006-01-02 15:04:05.000"))
	}
	if c.tenantScoping {
		params.Set(tenantSettingName, tenantID) // TENANT-004: DB-level scope
	}
	sql := fmt.Sprintf("SELECT tenant_id, agent_id, toString(window_start) AS window_start, src_workload, dst_workload, dst_port, l7_protocol, sum(bytes) AS bytes, sum(packets) AS packets, sum(connections) AS connections FROM %s FINAL WHERE %s GROUP BY tenant_id, agent_id, window_start, src_workload, dst_workload, dst_port, l7_protocol ORDER BY bytes DESC LIMIT %d FORMAT JSONEachRow",
		edgesTable, where, clampLimit(q.Limit))
	rows, err := c.queryParams(ctx, sql, params)
	if err != nil {
		return nil, err
	}
	out := make([]Edge, 0, len(rows))
	for _, r := range rows {
		out = append(out, Edge{
			TenantID: str(r["tenant_id"]), AgentID: str(r["agent_id"]),
			SrcWorkload: str(r["src_workload"]), DstWorkload: str(r["dst_workload"]),
			DstPort: uint16(num(r["dst_port"])), L7Protocol: str(r["l7_protocol"]),
			Bytes: uint64(num(r["bytes"])), Packets: uint64(num(r["packets"])),
			Connections: uint64(num(r["connections"])),
		})
	}
	return out, nil
}

// DeleteTenant erases a tenant's aggregates and verifies they are gone.
func (c *ClickHouse) DeleteTenant(ctx context.Context, tenantID string) (int64, error) {
	if tenantID == "" {
		return 0, ErrNoTenant
	}
	del := fmt.Sprintf("ALTER TABLE %s DELETE WHERE tenant_id={tenant:String}", edgesTable)
	if err := c.execParams(ctx, del, url.Values{"param_tenant": {tenantID}}); err != nil {
		return 0, err
	}
	rows, err := c.queryParams(ctx,
		fmt.Sprintf("SELECT count() AS n FROM %s WHERE tenant_id={tenant:String} FORMAT JSONEachRow", edgesTable),
		url.Values{"param_tenant": {tenantID}})
	if err != nil || len(rows) == 0 {
		return -1, err
	}
	return int64(num(rows[0]["n"])), nil
}

func (c *ClickHouse) Close() error { return nil }

// chUserRe validates a ClickHouse USER identifier in our DDL (identifiers
// cannot be bound parameters; validated, fail closed). Parity with flowstore.
var chUserRe = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_-]{0,62}$`)

func chValidUser(u string) error {
	if !chUserRe.MatchString(u) {
		return fmt.Errorf("refusing malformed ClickHouse user identifier %q", u)
	}
	return nil
}

// EnsureReaderRowPolicy installs the SETTING-SCOPED row policy (TENANT-004
// parity): the readerUser's SELECTs on the edges table are constrained to rows
// whose tenant_id equals the per-request custom setting SQL_probectl_tenant.
// An UNSET setting matches NO rows — fail closed.
func (c *ClickHouse) EnsureReaderRowPolicy(ctx context.Context, readerUser string) error {
	if err := chValidUser(readerUser); err != nil {
		return fmt.Errorf("ebpfstore: reader user: %w", err)
	}
	ddl := fmt.Sprintf(
		"CREATE ROW POLICY IF NOT EXISTS probectl_reader_scope ON %s FOR SELECT USING tenant_id = getSetting('%s') TO %s",
		edgesTable, tenantSettingName, readerUser)
	if err := c.exec(ctx, ddl, nil); err != nil {
		return fmt.Errorf("ebpfstore: reader row policy: %w", err)
	}
	return nil
}

// EnsureRowPolicies installs DB-LEVEL tenancy on the edges table (TENANT-004 /
// U-026 parity with flowstore): per-tenant CH users (named exactly the tenant
// id) are row-filtered to tenant_id = currentUser(); serviceUser keeps full
// access.
func (c *ClickHouse) EnsureRowPolicies(ctx context.Context, serviceUser string) error {
	if serviceUser == "" {
		serviceUser = "default"
	}
	if err := chValidUser(serviceUser); err != nil {
		return fmt.Errorf("ebpfstore: service user: %w", err)
	}
	for _, ddl := range []string{
		fmt.Sprintf("CREATE ROW POLICY IF NOT EXISTS probectl_tenant_isolation ON %s FOR SELECT USING tenant_id = currentUser() TO ALL EXCEPT %s", edgesTable, serviceUser),
		fmt.Sprintf("CREATE ROW POLICY IF NOT EXISTS probectl_service_access ON %s FOR SELECT USING 1 TO %s", edgesTable, serviceUser),
	} {
		if err := c.exec(ctx, ddl, nil); err != nil {
			return fmt.Errorf("ebpfstore: row policy: %w", err)
		}
	}
	return nil
}

// --- HTTP helpers over the shared chclient (CODE-006) ---

func (c *ClickHouse) exec(ctx context.Context, query string, body io.Reader) error {
	return c.execParams(ctx, query, nil, body)
}

func (c *ClickHouse) execParams(ctx context.Context, query string, params url.Values, body ...io.Reader) error {
	u := c.base + "/?query=" + url.QueryEscape(query)
	if len(params) > 0 {
		u += "&" + params.Encode()
	}
	var rdr io.Reader
	if len(body) > 0 {
		rdr = body[0]
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, rdr)
	if err != nil {
		return err
	}
	resp, err := c.conn.Do(c.base, req)
	if err != nil {
		return fmt.Errorf("ebpfstore: request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("ebpfstore: status %d: %s", resp.StatusCode, b)
	}
	return nil
}

func (c *ClickHouse) query(ctx context.Context, sql string) ([]map[string]any, error) {
	return c.queryParams(ctx, sql+" FORMAT JSONEachRow", nil)
}

func (c *ClickHouse) queryParams(ctx context.Context, sql string, params url.Values) ([]map[string]any, error) {
	u := c.base + "/?query=" + url.QueryEscape(sql)
	if len(params) > 0 {
		u += "&" + params.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.conn.Do(c.base, req)
	if err != nil {
		return nil, fmt.Errorf("ebpfstore: query: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("ebpfstore: query status %d: %s", resp.StatusCode, raw)
	}
	return chclient.Decode(raw)
}

func str(v any) string  { return chclient.String(v) }
func num(v any) float64 { return chclient.Float(v) }
