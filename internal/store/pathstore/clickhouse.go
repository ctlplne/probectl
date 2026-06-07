package pathstore

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/breaker"
	"github.com/imfeelingtheagi/probectl/internal/crypto"
	"github.com/imfeelingtheagi/probectl/internal/path"
	"github.com/imfeelingtheagi/probectl/internal/store/chmigrate"
)

// tenant_id is the partition key so a tenant's path data is physically separated
// (CLAUDE.md §4); it leads every ORDER BY so tenant-scoped reads prune by it.
const createHops = `CREATE TABLE IF NOT EXISTS probectl_path_hops (
  tenant_id String, path_id String, target String, target_ip String, mode String,
  ts DateTime64(3), ttl UInt8, responder String,
  sent UInt32, received UInt32, loss_ratio Float64,
  rtt_min_ms Float64, rtt_avg_ms Float64, rtt_max_ms Float64,
  mpls_labels Array(UInt32)
) ENGINE = MergeTree PARTITION BY tenant_id ORDER BY (tenant_id, target, ts, ttl, responder)`

const createLinks = `CREATE TABLE IF NOT EXISTS probectl_path_links (
  tenant_id String, path_id String, target String, ts DateTime64(3),
  ttl UInt8, from_ip String, to_ip String
) ENGINE = MergeTree PARTITION BY tenant_id ORDER BY (tenant_id, target, ts, ttl, from_ip, to_ip)`

// ClickHouse persists paths to a ClickHouse HTTP endpoint. TLS in transit is
// supported by using an https URL (CLAUDE.md §7 guardrail 12).
type ClickHouse struct {
	breaker *breaker.Breaker
	base    string
	client  *http.Client
}

// chMigrations is the pathstore's versioned ClickHouse schema (U-046),
// applied through internal/store/chmigrate with a server-side ledger.
// Shipped versions are immutable — schema changes are NEW versions with
// idempotent (IF NOT EXISTS / additive) statements.
func chMigrations() []chmigrate.Migration {
	return []chmigrate.Migration{
		{Version: 1, Name: "create_path_tables", Statements: []string{createHops, createLinks}},
	}
}

// chExec adapts the store's HTTP client to the chmigrate runner.
type chExec struct{ c *ClickHouse }

func (e chExec) Exec(ctx context.Context, sql string, p chmigrate.Params) error {
	return e.c.exec(ctx, sql, chParams(p), nil)
}
func (e chExec) Query(ctx context.Context, sql string, p chmigrate.Params) ([]map[string]any, error) {
	return e.c.query(ctx, sql, chParams(p))
}

// NewClickHouse connects to a ClickHouse HTTP endpoint and ensures the schema
// via versioned, ledger-recorded migrations (U-046).
func NewClickHouse(rawURL string) (*ClickHouse, error) {
	c := &ClickHouse{base: strings.TrimRight(rawURL, "/"), client: &http.Client{Timeout: 30 * time.Second}, breaker: breaker.New(0, 0)}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if _, err := chmigrate.Apply(ctx, chExec{c}, "pathstore", chMigrations(), nil); err != nil {
		return nil, fmt.Errorf("pathstore: migrate: %w", err)
	}
	return c, nil
}

type hopRow struct {
	TenantID  string   `json:"tenant_id"`
	PathID    string   `json:"path_id"`
	Target    string   `json:"target"`
	TargetIP  string   `json:"target_ip"`
	Mode      string   `json:"mode"`
	TS        string   `json:"ts"`
	TTL       int      `json:"ttl"`
	Responder string   `json:"responder"`
	Sent      int      `json:"sent"`
	Received  int      `json:"received"`
	LossRatio float64  `json:"loss_ratio"`
	RTTMin    float64  `json:"rtt_min_ms"`
	RTTAvg    float64  `json:"rtt_avg_ms"`
	RTTMax    float64  `json:"rtt_max_ms"`
	MPLS      []uint32 `json:"mpls_labels"`
}

type linkRow struct {
	TenantID string `json:"tenant_id"`
	PathID   string `json:"path_id"`
	Target   string `json:"target"`
	TS       string `json:"ts"`
	TTL      int    `json:"ttl"`
	From     string `json:"from_ip"`
	To       string `json:"to_ip"`
}

// Save writes one discovery (its hops and links) under tenantID.
// ErrNoTenant refuses any tenant-keyed ClickHouse operation without a tenant
// (U-026 defense in depth).
var ErrNoTenant = errors.New("pathstore: tenant_id is required (refusing an unscoped ClickHouse query)")

// EnsureRowPolicies installs DB-level tenancy on the path tables (U-026) —
// same model as flowstore: per-tenant CH users see only their rows;
// serviceUser keeps full access.
func (c *ClickHouse) EnsureRowPolicies(ctx context.Context, serviceUser string) error {
	if serviceUser == "" {
		serviceUser = "default"
	}
	if !chUserRe.MatchString(serviceUser) {
		return fmt.Errorf("pathstore: refusing malformed ClickHouse user identifier %q", serviceUser)
	}
	for _, table := range []string{"probectl_path_hops", "probectl_path_links"} {
		for _, ddl := range []string{
			fmt.Sprintf("CREATE ROW POLICY IF NOT EXISTS probectl_tenant_isolation ON %s FOR SELECT USING tenant_id = currentUser() TO ALL EXCEPT %s", table, serviceUser),
			fmt.Sprintf("CREATE ROW POLICY IF NOT EXISTS probectl_service_access ON %s FOR SELECT USING 1 TO %s", table, serviceUser),
		} {
			if err := c.exec(ctx, ddl, nil, nil); err != nil {
				return fmt.Errorf("pathstore: row policy: %w", err)
			}
		}
	}
	return nil
}

func (c *ClickHouse) Save(ctx context.Context, tenantID string, p *path.Path) error {
	if tenantID == "" {
		return ErrNoTenant
	}
	pathID, err := randomID()
	if err != nil {
		return err
	}
	ts := time.Now().UTC().Format("2006-01-02 15:04:05.000")

	var hops bytes.Buffer
	enc := json.NewEncoder(&hops)
	for _, h := range p.Hops {
		for _, n := range h.Nodes {
			labels := make([]uint32, 0, len(n.MPLS))
			for _, l := range n.MPLS {
				labels = append(labels, l.Label)
			}
			if err := enc.Encode(hopRow{
				TenantID: tenantID, PathID: pathID, Target: p.Target, TargetIP: p.TargetIP, Mode: p.Mode,
				TS: ts, TTL: h.TTL, Responder: n.IP, Sent: n.Sent, Received: n.Received, LossRatio: n.LossRatio,
				RTTMin: n.RTTMinMs, RTTAvg: n.RTTAvgMs, RTTMax: n.RTTMaxMs, MPLS: labels,
			}); err != nil {
				return err
			}
		}
	}
	if hops.Len() > 0 {
		if err := c.exec(ctx, "INSERT INTO probectl_path_hops FORMAT JSONEachRow", nil, &hops); err != nil {
			return err
		}
	}

	var links bytes.Buffer
	lenc := json.NewEncoder(&links)
	for _, l := range p.Links {
		if err := lenc.Encode(linkRow{
			TenantID: tenantID, PathID: pathID, Target: p.Target, TS: ts, TTL: l.TTL, From: l.From, To: l.To,
		}); err != nil {
			return err
		}
	}
	if links.Len() > 0 {
		if err := c.exec(ctx, "INSERT INTO probectl_path_links FORMAT JSONEachRow", nil, &links); err != nil {
			return err
		}
	}
	return nil
}

// Latest reconstructs the most recently saved path to target for a tenant from
// the hop + link rows.
// DeleteTenant removes every path row for the tenant from both tables
// (mutations_sync so the count-after is authoritative) and returns the
// pre-count and the verified remaining rows (U-027).
func (c *ClickHouse) DeleteTenant(ctx context.Context, tenantID string) (deleted, remaining int, err error) {
	if tenantID == "" {
		return 0, 0, ErrNoTenant
	}
	tp := chParams{"tenant": tenantID}
	for _, table := range []string{"probectl_path_hops", "probectl_path_links"} {
		out, qerr := c.query(ctx, "SELECT count() AS n FROM "+table+" WHERE tenant_id={tenant:String}", tp)
		if qerr != nil {
			return deleted, -1, qerr
		}
		deleted += chCount(out)
		if eerr := c.exec(ctx, "DELETE FROM "+table+" WHERE tenant_id={tenant:String} SETTINGS mutations_sync=2", tp, nil); eerr != nil {
			return deleted, -1, eerr
		}
		out, qerr = c.query(ctx, "SELECT count() AS n FROM "+table+" WHERE tenant_id={tenant:String}", tp)
		if qerr != nil {
			return deleted, -1, qerr
		}
		remaining += chCount(out)
	}
	return deleted, remaining, nil
}

func (c *ClickHouse) Latest(ctx context.Context, tenantID, target string) (*path.Path, bool, error) {
	if tenantID == "" {
		return nil, false, ErrNoTenant
	}
	meta, err := c.query(ctx,
		`SELECT path_id, target_ip, mode FROM probectl_path_hops WHERE tenant_id={tenant:String} AND target={target:String} ORDER BY ts DESC LIMIT 1`,
		chParams{"tenant": tenantID, "target": target})
	if err != nil {
		return nil, false, err
	}
	if len(meta) == 0 {
		return nil, false, nil
	}
	pathID := chToString(meta[0]["path_id"])
	p := &path.Path{Target: target, TargetIP: chToString(meta[0]["target_ip"]), Mode: chToString(meta[0]["mode"])}

	hopRows, err := c.query(ctx,
		`SELECT ttl, responder, sent, received, loss_ratio, rtt_min_ms, rtt_avg_ms, rtt_max_ms, mpls_labels
		 FROM probectl_path_hops WHERE tenant_id={tenant:String} AND path_id={path:String} ORDER BY ttl, responder`,
		chParams{"tenant": tenantID, "path": pathID})
	if err != nil {
		return nil, false, err
	}
	byTTL := map[int]*path.Hop{}
	var order []int
	maxTTL := 0
	for _, r := range hopRows {
		ttl := chToInt(r["ttl"])
		h := byTTL[ttl]
		if h == nil {
			h = &path.Hop{TTL: ttl}
			byTTL[ttl] = h
			order = append(order, ttl)
		}
		node := path.HopNode{
			IP: chToString(r["responder"]), Sent: chToInt(r["sent"]), Received: chToInt(r["received"]),
			LossRatio: chToFloat(r["loss_ratio"]), RTTMinMs: chToFloat(r["rtt_min_ms"]),
			RTTAvgMs: chToFloat(r["rtt_avg_ms"]), RTTMaxMs: chToFloat(r["rtt_max_ms"]),
		}
		for _, l := range chToUintSlice(r["mpls_labels"]) {
			node.MPLS = append(node.MPLS, path.MPLSLabel{Label: l})
		}
		if node.IP == p.TargetIP {
			p.DestinationReached = true
		}
		h.Nodes = append(h.Nodes, node)
		if ttl > maxTTL {
			maxTTL = ttl
		}
	}
	sort.Ints(order)
	for _, ttl := range order {
		p.Hops = append(p.Hops, *byTTL[ttl])
	}
	p.MaxHops = maxTTL

	linkRows, err := c.query(ctx,
		`SELECT ttl, from_ip, to_ip FROM probectl_path_links WHERE tenant_id={tenant:String} AND path_id={path:String} ORDER BY ttl, from_ip, to_ip`,
		chParams{"tenant": tenantID, "path": pathID})
	if err != nil {
		return nil, false, err
	}
	for _, r := range linkRows {
		p.Links = append(p.Links, path.Link{TTL: chToInt(r["ttl"]), From: chToString(r["from_ip"]), To: chToString(r["to_ip"])})
	}
	return p, true, nil
}

// Close is a no-op (the HTTP client needs no teardown).
func (c *ClickHouse) Close() error { return nil }

// chParams carries SERVER-BOUND query parameters (SEC-005/TENANT-108): each
// key k is sent as the HTTP parameter param_k and bound by ClickHouse to the
// {k:Type} placeholder in the SQL — values never enter the SQL text.
type chParams map[string]string

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

// query runs a SELECT and parses the JSONEachRow response into row maps.
func (c *ClickHouse) query(ctx context.Context, sql string, p chParams) ([]map[string]any, error) {
	u := c.base + "/?query=" + url.QueryEscape(sql+" FORMAT JSONEachRow") + p.qs()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := chDo(c.breaker, c.client, req)
	if err != nil {
		return nil, fmt.Errorf("pathstore: clickhouse query: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("pathstore: clickhouse query status %d: %s", resp.StatusCode, body)
	}
	var rows []map[string]any
	for _, line := range bytes.Split(body, []byte("\n")) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var row map[string]any
		if err := json.Unmarshal(line, &row); err != nil {
			return nil, fmt.Errorf("pathstore: decode row: %w", err)
		}
		rows = append(rows, row)
	}
	return rows, nil
}

// chDo issues the request through the circuit breaker (U-078).
func chDo(b *breaker.Breaker, client *http.Client, req *http.Request) (*http.Response, error) {
	var resp *http.Response
	err := b.Do(func() error {
		r, e := client.Do(req) //nolint:bodyclose // the response escapes to chDo's caller, which closes it
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

// chUserRe is the shape a ClickHouse USER identifier may take in our DDL
// (identifiers cannot be bound parameters; validated, fail closed).
var chUserRe = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_-]{0,62}$`)

// chCount extracts the single count() value from a query result.
func chCount(rows []map[string]any) int {
	if len(rows) == 0 {
		return 0
	}
	switch v := rows[0]["n"].(type) {
	case float64:
		return int(v)
	case string:
		n := 0
		for _, r := range v {
			if r < '0' || r > '9' {
				return 0
			}
			n = n*10 + int(r-'0')
		}
		return n
	}
	return 0
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
		f, _ := strconv.ParseFloat(n, 64)
		return f
	}
	return 0
}

func chToInt(v any) int { return int(chToFloat(v)) }

func chToUintSlice(v any) []uint32 {
	arr, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]uint32, 0, len(arr))
	for _, e := range arr {
		out = append(out, uint32(chToFloat(e)))
	}
	return out
}

func (c *ClickHouse) exec(ctx context.Context, query string, p chParams, body io.Reader) error {
	u := c.base + "/?query=" + url.QueryEscape(query) + p.qs()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, body)
	if err != nil {
		return err
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("pathstore: clickhouse request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("pathstore: clickhouse status %d: %s", resp.StatusCode, b)
	}
	return nil
}

func randomID() (string, error) {
	b, err := crypto.Random(16)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
