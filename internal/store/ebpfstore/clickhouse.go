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
	"strings"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/breaker"
	"github.com/imfeelingtheagi/probectl/internal/crypto"
	"github.com/imfeelingtheagi/probectl/internal/store/chmigrate"
)

const edgesTable = "probectl_ebpf_edges"

// ClickHouse persists eBPF aggregates over the ClickHouse HTTP interface
// (flowstore/otelstore pattern: no driver dependency; https URL = TLS in
// transit; a circuit breaker short-circuits a down upstream).
type ClickHouse struct {
	base    string
	client  *http.Client
	breaker *breaker.Breaker
}

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
		base:    strings.TrimRight(rawURL, "/"),
		client:  crypto.HardenedHTTPClient(30 * time.Second),
		breaker: breaker.New(0, 0),
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
	return c.exec(ctx, "INSERT INTO "+edgesTable+" FORMAT JSONEachRow", &buf)
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

// --- HTTP helpers (breaker-guarded; flowstore idiom) ---

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
	resp, err := c.do(req)
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
	resp, err := c.do(req)
	if err != nil {
		return nil, fmt.Errorf("ebpfstore: query: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("ebpfstore: query status %d: %s", resp.StatusCode, raw)
	}
	var rows []map[string]any
	for _, line := range bytes.Split(raw, []byte("\n")) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal(line, &m); err != nil {
			return nil, fmt.Errorf("ebpfstore: decode row: %w", err)
		}
		rows = append(rows, m)
	}
	return rows, nil
}

func (c *ClickHouse) do(req *http.Request) (*http.Response, error) {
	var resp *http.Response
	err := c.breaker.Do(func() error {
		r, e := c.client.Do(req) //nolint:bodyclose // escapes to caller
		if e != nil {
			return e
		}
		resp = r
		return nil
	})
	return resp, err
}

func str(v any) string {
	s, _ := v.(string)
	return s
}

func num(v any) float64 {
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
