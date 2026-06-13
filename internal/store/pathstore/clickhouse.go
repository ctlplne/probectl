// SPDX-License-Identifier: LicenseRef-probectl-TBD

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
	"strings"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/breaker"
	"github.com/imfeelingtheagi/probectl/internal/crypto"
	"github.com/imfeelingtheagi/probectl/internal/path"
	"github.com/imfeelingtheagi/probectl/internal/store/chclient"
	"github.com/imfeelingtheagi/probectl/internal/store/chmigrate"
)

// (tenant_id, day) is the partition key (Sprint 16, SCALE-006 — the flowstore
// pattern): a tenant's path data is physically separated (CLAUDE.md §4) AND
// the retention TTL drops whole day-parts cheaply instead of mutating rows.
// tenant_id leads every ORDER BY so tenant-scoped reads prune by it.
const (
	hopsTable  = "probectl_path_hops2"
	linksTable = "probectl_path_links2"
)

const createHops = `CREATE TABLE IF NOT EXISTS ` + hopsTable + ` (
  tenant_id String, path_id String, target String, target_ip String, mode String,
  ts DateTime64(3), ttl UInt8, responder String,
  sent UInt32, received UInt32, loss_ratio Float64,
  rtt_min_ms Float64, rtt_avg_ms Float64, rtt_max_ms Float64,
  mpls_labels Array(UInt32)
) ENGINE = MergeTree PARTITION BY (tenant_id, toYYYYMMDD(ts)) ORDER BY (tenant_id, target, ts, ttl, responder)`

const createLinks = `CREATE TABLE IF NOT EXISTS ` + linksTable + ` (
  tenant_id String, path_id String, target String, ts DateTime64(3),
  ttl UInt8, from_ip String, to_ip String
) ENGINE = MergeTree PARTITION BY (tenant_id, toYYYYMMDD(ts)) ORDER BY (tenant_id, target, ts, ttl, from_ip, to_ip)`

// ClickHouse persists paths to a ClickHouse HTTP endpoint. TLS in transit is
// supported by using an https URL (CLAUDE.md §7 guardrail 12).
type ClickHouse struct {
	base string
	conn *chclient.Conn // shared transport (TLS client + breaker), CODE-006
	// tenantScoping (TENANT-004): attach the per-request tenant custom setting
	// to tenant-scoped reads so the setting-scoped reader row policy can
	// constrain the query path at the DB. Off by default; defaulted on by the
	// multi-tenant/regulated profile.
	tenantScoping bool
}

// tenantSettingName is the ClickHouse custom setting carrying the request
// tenant; the setting-scoped reader row policy binds SELECTs to getSetting()
// of it (parity with flowstore/otelstore/ebpfstore).
const tenantSettingName = "SQL_probectl_tenant"

// WithTenantScoping enables per-request custom-setting tenant scoping on reads
// (pair with EnsureReaderRowPolicy on the reader user).
func (c *ClickHouse) WithTenantScoping(on bool) *ClickHouse { c.tenantScoping = on; return c }

// chMigrations is the pathstore's versioned ClickHouse schema (U-046),
// applied through internal/store/chmigrate with a server-side ledger.
// Shipped versions are immutable — schema changes are NEW versions with
// idempotent (IF NOT EXISTS / additive) statements.
func chMigrations() []chmigrate.Migration {
	return []chmigrate.Migration{
		{Version: 1, Name: "create_path_tables", Statements: []string{createHopsV1, createLinksV1}},
		// v2 (Sprint 16, SCALE-006): (tenant_id, day) partitioning so the
		// retention TTL drops whole parts. PARTITION BY is immutable in
		// ClickHouse, so v2 creates NEW tables and DROPS the v1 ones —
		// pre-GA, with path snapshots being re-discoverable caches, the
		// discard is deliberate.
		{Version: 2, Name: "path_tables_day_partitioned", Statements: []string{
			createHops, createLinks,
			"DROP TABLE IF EXISTS probectl_path_hops",
			"DROP TABLE IF EXISTS probectl_path_links",
		}},
	}
}

// v1 DDL stays VERBATIM (shipped versions are immutable — the ledger checksum
// refuses drift); v2 supersedes it.
const createHopsV1 = `CREATE TABLE IF NOT EXISTS probectl_path_hops (
  tenant_id String, path_id String, target String, target_ip String, mode String,
  ts DateTime64(3), ttl UInt8, responder String,
  sent UInt32, received UInt32, loss_ratio Float64,
  rtt_min_ms Float64, rtt_avg_ms Float64, rtt_max_ms Float64,
  mpls_labels Array(UInt32)
) ENGINE = MergeTree PARTITION BY tenant_id ORDER BY (tenant_id, target, ts, ttl, responder)`

const createLinksV1 = `CREATE TABLE IF NOT EXISTS probectl_path_links (
  tenant_id String, path_id String, target String, ts DateTime64(3),
  ttl UInt8, from_ip String, to_ip String
) ENGINE = MergeTree PARTITION BY tenant_id ORDER BY (tenant_id, target, ts, ttl, from_ip, to_ip)`

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
func NewClickHouse(rawURL string) (*ClickHouse, error) { return NewClickHouseRetained(rawURL, 0) }

// NewClickHouseRetained is NewClickHouse plus the boot-applied retention TTL
// (Sprint 16, SCALE-006 — the flowstore pattern: runtime config, not schema).
// retentionDays > 0 ALTERs a delete-TTL onto both path tables, idempotently.
func NewClickHouseRetained(rawURL string, retentionDays int) (*ClickHouse, error) {
	c := &ClickHouse{base: strings.TrimRight(rawURL, "/"), conn: chclient.New(30 * time.Second)}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if _, err := chmigrate.Apply(ctx, chExec{c}, "pathstore", chMigrations(), nil); err != nil {
		return nil, fmt.Errorf("pathstore: migrate: %w", err)
	}
	if retentionDays > 0 {
		for _, table := range []string{hopsTable, linksTable} {
			ttl := fmt.Sprintf("ALTER TABLE %s MODIFY TTL toDateTime(ts) + INTERVAL %d DAY DELETE", table, retentionDays)
			if err := c.exec(ctx, ttl, nil, nil); err != nil {
				return nil, fmt.Errorf("pathstore: apply retention TTL: %w", err)
			}
		}
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

// EnsureReaderRowPolicy installs the SETTING-SCOPED row policy (TENANT-004
// parity): the readerUser's SELECTs on the path tables are constrained to rows
// whose tenant_id equals the per-request custom setting SQL_probectl_tenant.
// An UNSET setting matches NO rows — fail closed.
func (c *ClickHouse) EnsureReaderRowPolicy(ctx context.Context, readerUser string) error {
	if !chUserRe.MatchString(readerUser) {
		return fmt.Errorf("pathstore: refusing malformed ClickHouse user identifier %q", readerUser)
	}
	for _, table := range []string{hopsTable, linksTable} {
		ddl := fmt.Sprintf(
			"CREATE ROW POLICY IF NOT EXISTS probectl_reader_scope ON %s FOR SELECT USING tenant_id = getSetting('%s') TO %s",
			table, tenantSettingName, readerUser)
		if err := c.exec(ctx, ddl, nil, nil); err != nil {
			return fmt.Errorf("pathstore: reader row policy: %w", err)
		}
	}
	return nil
}

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
	for _, table := range []string{hopsTable, linksTable} {
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
	return c.SaveBatch(ctx, []PathItem{{TenantID: tenantID, P: p}})
}

// SaveBatch persists MANY discoveries in one insert per table (Sprint 14,
// SCALE-009 — the cross-path batching window): N paths cost 2 requests, not
// 2N. Used by BatchingSaver; Save is the single-item case.
func (c *ClickHouse) SaveBatch(ctx context.Context, items []PathItem) error {
	var hops, links bytes.Buffer
	henc, lenc := json.NewEncoder(&hops), json.NewEncoder(&links)
	for _, it := range items {
		if it.TenantID == "" {
			return ErrNoTenant
		}
		pathID, err := randomID()
		if err != nil {
			return err
		}
		ts := time.Now().UTC().Format("2006-01-02 15:04:05.000")
		for _, h := range it.P.Hops {
			for _, n := range h.Nodes {
				labels := make([]uint32, 0, len(n.MPLS))
				for _, l := range n.MPLS {
					labels = append(labels, l.Label)
				}
				if err := henc.Encode(hopRow{
					TenantID: it.TenantID, PathID: pathID, Target: it.P.Target, TargetIP: it.P.TargetIP, Mode: it.P.Mode,
					TS: ts, TTL: h.TTL, Responder: n.IP, Sent: n.Sent, Received: n.Received, LossRatio: n.LossRatio,
					RTTMin: n.RTTMinMs, RTTAvg: n.RTTAvgMs, RTTMax: n.RTTMaxMs, MPLS: labels,
				}); err != nil {
					return err
				}
			}
		}
		for _, l := range it.P.Links {
			if err := lenc.Encode(linkRow{
				TenantID: it.TenantID, PathID: pathID, Target: it.P.Target, TS: ts, TTL: l.TTL, From: l.From, To: l.To,
			}); err != nil {
				return err
			}
		}
	}
	if hops.Len() > 0 {
		if err := c.exec(ctx, "INSERT INTO "+hopsTable+" FORMAT JSONEachRow", nil, &hops); err != nil {
			return err
		}
	}
	if links.Len() > 0 {
		if err := c.exec(ctx, "INSERT INTO "+linksTable+" FORMAT JSONEachRow", nil, &links); err != nil {
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
	for _, table := range []string{hopsTable, linksTable} {
		out, qerr := c.queryScoped(ctx, tenantID, "SELECT count() AS n FROM "+table+" WHERE tenant_id={tenant:String}", tp)
		if qerr != nil {
			return deleted, -1, qerr
		}
		deleted += chCount(out)
		if eerr := c.exec(ctx, "DELETE FROM "+table+" WHERE tenant_id={tenant:String} SETTINGS mutations_sync=2", tp, nil); eerr != nil {
			return deleted, -1, eerr
		}
		out, qerr = c.queryScoped(ctx, tenantID, "SELECT count() AS n FROM "+table+" WHERE tenant_id={tenant:String}", tp)
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
	// CORRECT-010: select the SINGLE newest snapshot (ORDER BY ts DESC LIMIT 1),
	// then read exactly that path_id's hops/links below. This newest-only read is
	// what makes a redelivered duplicate save harmless — it is never aggregated
	// across snapshots, so no dedup engine is needed (see doc.go). Do not widen
	// this to a cross-snapshot scan.
	meta, err := c.queryScoped(ctx, tenantID,
		"SELECT path_id, target_ip, mode FROM "+hopsTable+" WHERE tenant_id={tenant:String} AND target={target:String} ORDER BY ts DESC LIMIT 1",
		chParams{"tenant": tenantID, "target": target})
	if err != nil {
		return nil, false, err
	}
	if len(meta) == 0 {
		return nil, false, nil
	}
	pathID := chToString(meta[0]["path_id"])
	p := &path.Path{Target: target, TargetIP: chToString(meta[0]["target_ip"]), Mode: chToString(meta[0]["mode"])}

	hopRows, err := c.queryScoped(ctx, tenantID,
		"SELECT ttl, responder, sent, received, loss_ratio, rtt_min_ms, rtt_avg_ms, rtt_max_ms, mpls_labels FROM "+hopsTable+" WHERE tenant_id={tenant:String} AND path_id={path:String} ORDER BY ttl, responder",
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

	linkRows, err := c.queryScoped(ctx, tenantID,
		"SELECT ttl, from_ip, to_ip FROM "+linksTable+" WHERE tenant_id={tenant:String} AND path_id={path:String} ORDER BY ttl, from_ip, to_ip",
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

// queryScoped is query with the per-request tenant custom setting attached
// (TENANT-004) when scoping is enabled, so the reader row policy can constrain
// the result at the DB. tenant "" means an admin/cross-tenant read (none here).
func (c *ClickHouse) queryScoped(ctx context.Context, tenant, sql string, p chParams) ([]map[string]any, error) {
	if !c.tenantScoping || tenant == "" {
		return c.query(ctx, sql, p)
	}
	u := c.base + "/?query=" + url.QueryEscape(sql+" FORMAT JSONEachRow") + p.qs() +
		"&" + tenantSettingName + "=" + url.QueryEscape(tenant)
	return c.doQuery(ctx, u)
}

// query runs a SELECT and parses the JSONEachRow response into row maps.
func (c *ClickHouse) query(ctx context.Context, sql string, p chParams) ([]map[string]any, error) {
	return c.doQuery(ctx, c.base+"/?query="+url.QueryEscape(sql+" FORMAT JSONEachRow")+p.qs())
}

func (c *ClickHouse) doQuery(ctx context.Context, u string) ([]map[string]any, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.conn.Do("", req)
	if err != nil {
		return nil, fmt.Errorf("pathstore: clickhouse query: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("pathstore: clickhouse query status %d: %s", resp.StatusCode, body)
	}
	return chclient.Decode(body)
}

// BreakerStats exposes the storage breaker state (U-078 fallback metrics).
func (c *ClickHouse) BreakerStats() breaker.Stats { return c.conn.Stats() }

// chUserRe is the shape a ClickHouse USER identifier may take in our DDL
// (identifiers cannot be bound parameters; validated, fail closed).
var chUserRe = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_-]{0,62}$`)

// ClickHouse result coercions — shared via chclient (CODE-006).
func chCount(rows []map[string]any) int { return chclient.Count(rows) }
func chToString(v any) string           { return chclient.String(v) }
func chToFloat(v any) float64           { return chclient.Float(v) }
func chToInt(v any) int                 { return chclient.Int(v) }
func chToUintSlice(v any) []uint32      { return chclient.UintSlice(v) }

func (c *ClickHouse) exec(ctx context.Context, query string, p chParams, body io.Reader) error {
	u := c.base + "/?query=" + url.QueryEscape(query) + p.qs()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, body)
	if err != nil {
		return err
	}
	resp, err := c.conn.Do("", req)
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
