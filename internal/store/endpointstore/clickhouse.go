// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package endpointstore

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/store/chclient"
	"github.com/ctlplne/probectl/internal/store/chmigrate"
)

const (
	eventsTable      = "probectl_endpoint_events"
	tenantSetting    = "SQL_probectl_tenant"
	maxLatestResults = 22_000 // 2k endpoints × (4 singleton + 10 sessions), rounded.
)

func eventsDDL(table string) string {
	return `CREATE TABLE IF NOT EXISTS ` + table + ` (
  tenant_id String,
  agent_id String,
  signal_type LowCardinality(String),
  signal_key String,
  target String,
  success Bool,
  error String,
  metrics_json String,
  attributes_json String,
  observed_at DateTime64(6),
  event_id String
) ENGINE = ReplacingMergeTree
PARTITION BY (tenant_id, toYYYYMMDD(observed_at))
ORDER BY (tenant_id, observed_at, agent_id, signal_type, signal_key, event_id)`
}

func chMigrationsFor(table string) []chmigrate.Migration {
	return []chmigrate.Migration{{Version: 1, Name: "create_endpoint_events", Statements: []string{eventsDDL(table)}}}
}

func chMigrations() []chmigrate.Migration { return chMigrationsFor(eventsTable) }

// CHMigrations exposes the endpoint ClickHouse schema to the migration gate.
func CHMigrations() []chmigrate.Migration { return chMigrations() }

// Target is a pooled or per-tenant ClickHouse destination.
type Target struct {
	BaseURL  string
	Database string
}

// TargetRouter resolves tenant storage using the operation context. Errors fail
// the operation closed.
type TargetRouter func(ctx context.Context, tenantID string) (Target, error)

var (
	chIdentRe = regexp.MustCompile(`^[a-z_][a-z0-9_]{0,62}$`)
	chUserRe  = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_-]{0,62}$`)
)

func tableFor(target Target) (string, error) {
	if target.Database == "" {
		return eventsTable, nil
	}
	if !chIdentRe.MatchString(target.Database) {
		return "", fmt.Errorf("endpointstore: refusing malformed database name %q", target.Database)
	}
	return target.Database + "." + eventsTable, nil
}

// ClickHouse is the durable endpoint event store.
type ClickHouse struct {
	base         string
	conn         *chclient.Conn
	router       TargetRouter
	tenantScoped bool
}

// NewClickHouseWithClient uses a caller-supplied hardened transport when the
// deployment authenticates ClickHouse without URL userinfo, then applies the
// idempotent v1 schema and optional retention TTL.
func NewClickHouseWithClient(rawURL string, retentionDays int, client *http.Client) (*ClickHouse, error) {
	c := &ClickHouse{base: strings.TrimRight(rawURL, "/"), conn: chclient.NewWithClient(client)}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if _, err := chmigrate.Apply(ctx, endpointCHExec{store: c}, "endpointstore", chMigrations(), nil); err != nil {
		return nil, fmt.Errorf("endpointstore: migrate: %w", err)
	}
	if err := c.applyTTL(ctx, Target{}, retentionDays); err != nil {
		return nil, err
	}
	return c, nil
}

// WithRouter installs per-tenant silo/residency routing.
func (c *ClickHouse) WithRouter(router TargetRouter) *ClickHouse { c.router = router; return c }

// WithTenantScoping enables the custom-setting used by the reader row policy.
func (c *ClickHouse) WithTenantScoping(enabled bool) *ClickHouse { c.tenantScoped = enabled; return c }

func (c *ClickHouse) route(ctx context.Context, tenantID string) (Target, error) {
	if tenantID == "" {
		return Target{}, ErrNoTenant
	}
	if c.router == nil {
		return Target{}, nil
	}
	return c.router(ctx, tenantID)
}

// EnsureTenantDatabase provisions the endpoint table in a siloed database.
func (c *ClickHouse) EnsureTenantDatabase(ctx context.Context, target Target, retentionDays int) error {
	if target.Database == "" || !chIdentRe.MatchString(target.Database) {
		return fmt.Errorf("endpointstore: refusing malformed database name %q", target.Database)
	}
	if err := c.execAt(ctx, target.BaseURL, "CREATE DATABASE IF NOT EXISTS "+target.Database, nil, nil); err != nil {
		return err
	}
	table, _ := tableFor(target)
	if _, err := chmigrate.Apply(ctx, endpointCHExec{store: c, base: target.BaseURL}, "endpointstore:"+target.Database, chMigrationsFor(table), nil); err != nil {
		return err
	}
	return c.applyTTL(ctx, target, retentionDays)
}

// DropTenantDatabase removes a routed tenant's entire database.
func (c *ClickHouse) DropTenantDatabase(ctx context.Context, target Target) error {
	if target.Database == "" || !chIdentRe.MatchString(target.Database) {
		return fmt.Errorf("endpointstore: refusing to drop malformed database name %q", target.Database)
	}
	return c.execAt(ctx, target.BaseURL, "DROP DATABASE IF EXISTS "+target.Database, nil, nil)
}

func (c *ClickHouse) applyTTL(ctx context.Context, target Target, retentionDays int) error {
	if retentionDays <= 0 {
		return nil
	}
	table, err := tableFor(target)
	if err != nil {
		return err
	}
	query := fmt.Sprintf("ALTER TABLE %s MODIFY TTL toDateTime(observed_at) + INTERVAL %d DAY DELETE", table, retentionDays)
	if err := c.execAt(ctx, target.BaseURL, query, nil, nil); err != nil {
		return fmt.Errorf("endpointstore: apply retention TTL: %w", err)
	}
	return nil
}

type chEvent struct {
	TenantID       string `json:"tenant_id"`
	AgentID        string `json:"agent_id"`
	SignalType     string `json:"signal_type"`
	SignalKey      string `json:"signal_key"`
	Target         string `json:"target"`
	Success        bool   `json:"success"`
	Error          string `json:"error"`
	MetricsJSON    string `json:"metrics_json"`
	AttributesJSON string `json:"attributes_json"`
	ObservedAt     string `json:"observed_at"`
	EventID        string `json:"event_id"`
}

// Insert writes events grouped by routed tenant target. ReplacingMergeTree and
// event_id make at-least-once redelivery idempotent.
func (c *ClickHouse) Insert(ctx context.Context, events []Event) error {
	if len(events) == 0 {
		return nil
	}
	if err := validate(events); err != nil {
		return err
	}
	groups := map[Target][]Event{}
	for _, event := range events {
		target, err := c.route(ctx, event.TenantID)
		if err != nil {
			return fmt.Errorf("endpointstore: route tenant %s: %w", event.TenantID, err)
		}
		groups[target] = append(groups[target], event)
	}
	for target, group := range groups {
		table, err := tableFor(target)
		if err != nil {
			return err
		}
		var body bytes.Buffer
		enc := json.NewEncoder(&body)
		for _, event := range group {
			metrics, _ := json.Marshal(event.Metrics)
			attributes, _ := json.Marshal(event.Attributes)
			row := chEvent{
				TenantID: event.TenantID, AgentID: event.AgentID, SignalType: event.Type,
				SignalKey: event.SignalKey, Target: event.Target, Success: event.Success, Error: event.Error,
				MetricsJSON: string(metrics), AttributesJSON: string(attributes),
				ObservedAt: event.ObservedAt.UTC().Format("2006-01-02 15:04:05.000000"), EventID: eventID(event),
			}
			if err := enc.Encode(row); err != nil {
				return fmt.Errorf("endpointstore: encode: %w", err)
			}
		}
		query := "INSERT INTO " + table + " SETTINGS async_insert=1, wait_for_async_insert=1 FORMAT JSONEachRow"
		if err := c.execAt(ctx, target.BaseURL, query, nil, &body); err != nil {
			return err
		}
	}
	return nil
}

func eventID(event Event) string {
	payload, _ := json.Marshal(event)
	hash := crypto.Hash(payload)
	return fmt.Sprintf("%x", hash[:16])
}

// Latest returns only one tenant's newest event per endpoint signal identity.
func (c *ClickHouse) Latest(ctx context.Context, tenantID string) ([]Event, error) {
	target, err := c.route(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	table, err := tableFor(target)
	if err != nil {
		return nil, err
	}
	params := boundParams(map[string]string{"tenant": tenantID})
	if c.tenantScoped {
		params.Set(tenantSetting, tenantID)
	}
	query := fmt.Sprintf("SELECT tenant_id, agent_id, signal_type, signal_key, target, success, error, metrics_json, attributes_json, toString(observed_at) AS observed_at FROM %s FINAL WHERE tenant_id={tenant:String} ORDER BY observed_at DESC LIMIT 1 BY agent_id, signal_type, signal_key LIMIT %d FORMAT JSONEachRow", table, maxLatestResults)
	rows, err := c.queryAt(ctx, target.BaseURL, query, params)
	if err != nil {
		return nil, err
	}
	out := make([]Event, 0, len(rows))
	for _, row := range rows {
		event, err := decodeEvent(row)
		if err != nil {
			return nil, err
		}
		if event.TenantID != tenantID {
			return nil, fmt.Errorf("endpointstore: storage boundary returned tenant %q for %q", event.TenantID, tenantID)
		}
		out = append(out, event)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ObservedAt.Before(out[j].ObservedAt) })
	return out, nil
}

func decodeEvent(row map[string]any) (Event, error) {
	observed, err := parseCHTime(chclient.String(row["observed_at"]))
	if err != nil {
		return Event{}, err
	}
	event := Event{
		TenantID: chclient.String(row["tenant_id"]), AgentID: chclient.String(row["agent_id"]),
		Type: chclient.String(row["signal_type"]), SignalKey: chclient.String(row["signal_key"]),
		Target: chclient.String(row["target"]), Success: cellBool(row["success"]),
		Error: chclient.String(row["error"]), ObservedAt: observed,
	}
	if raw := chclient.String(row["metrics_json"]); raw != "" && raw != "null" {
		if err := json.Unmarshal([]byte(raw), &event.Metrics); err != nil {
			return Event{}, fmt.Errorf("endpointstore: decode metrics: %w", err)
		}
	}
	if raw := chclient.String(row["attributes_json"]); raw != "" && raw != "null" {
		if err := json.Unmarshal([]byte(raw), &event.Attributes); err != nil {
			return Event{}, fmt.Errorf("endpointstore: decode attributes: %w", err)
		}
	}
	return event, nil
}

func cellBool(value any) bool {
	if typed, ok := value.(bool); ok {
		return typed
	}
	return chclient.Uint64(value) != 0
}

func parseCHTime(raw string) (time.Time, error) {
	for _, layout := range []string{"2006-01-02 15:04:05.999999999", "2006-01-02T15:04:05.999999999Z07:00", time.RFC3339Nano} {
		if parsed, err := time.Parse(layout, raw); err == nil {
			return parsed.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("endpointstore: invalid observed_at %q", raw)
}

// PruneTenantBefore enforces a tenant-specific tighter retention window.
func (c *ClickHouse) PruneTenantBefore(ctx context.Context, tenantID string, cutoff time.Time) (int, error) {
	target, err := c.route(ctx, tenantID)
	if err != nil {
		return 0, err
	}
	table, err := tableFor(target)
	if err != nil {
		return 0, err
	}
	params := boundParams(map[string]string{"tenant": tenantID, "cutoff": cutoff.UTC().Format("2006-01-02 15:04:05.000000")})
	countRows, err := c.queryAt(ctx, target.BaseURL, "SELECT count() AS n FROM "+table+" WHERE tenant_id={tenant:String} AND observed_at < {cutoff:DateTime64(6)} FORMAT JSONEachRow", params)
	if err != nil {
		return 0, err
	}
	deleted := chclient.Count(countRows)
	query := "ALTER TABLE " + table + " DELETE WHERE tenant_id={tenant:String} AND observed_at < {cutoff:DateTime64(6)} SETTINGS mutations_sync=2"
	if err := c.execAt(ctx, target.BaseURL, query, params, nil); err != nil {
		return 0, err
	}
	return deleted, nil
}

// DeleteTenant erases a pooled tenant's rows or drops its routed database, then
// verifies zero remaining rows.
func (c *ClickHouse) DeleteTenant(ctx context.Context, tenantID string) (int64, error) {
	target, err := c.route(ctx, tenantID)
	if err != nil {
		return -1, err
	}
	if target.Database != "" {
		if err := c.DropTenantDatabase(ctx, target); err != nil {
			return -1, err
		}
		return 0, nil
	}
	params := boundParams(map[string]string{"tenant": tenantID})
	if err := c.execAt(ctx, target.BaseURL, "ALTER TABLE "+eventsTable+" DELETE WHERE tenant_id={tenant:String} SETTINGS mutations_sync=2", params, nil); err != nil {
		return -1, err
	}
	rows, err := c.queryAt(ctx, target.BaseURL, "SELECT count() AS n FROM "+eventsTable+" WHERE tenant_id={tenant:String} FORMAT JSONEachRow", params)
	if err != nil {
		return -1, err
	}
	return int64(chclient.Count(rows)), nil
}

// ExportTenant streams one tenant's event history as JSONL.
func (c *ClickHouse) ExportTenant(ctx context.Context, tenantID string, w io.Writer) (int64, error) {
	target, err := c.route(ctx, tenantID)
	if err != nil {
		return 0, err
	}
	table, err := tableFor(target)
	if err != nil {
		return 0, err
	}
	params := boundParams(map[string]string{"tenant": tenantID})
	if c.tenantScoped {
		params.Set(tenantSetting, tenantID)
	}
	query := "SELECT tenant_id, agent_id, signal_type, signal_key, target, success, error, metrics_json, attributes_json, toString(observed_at) AS observed_at FROM " + table + " FINAL WHERE tenant_id={tenant:String} ORDER BY observed_at FORMAT JSONEachRow"
	rows, err := c.queryAt(ctx, target.BaseURL, query, params)
	if err != nil {
		return 0, err
	}
	enc := json.NewEncoder(w)
	for i, row := range rows {
		event, err := decodeEvent(row)
		if err != nil {
			return int64(i), err
		}
		if event.TenantID != tenantID {
			return int64(i), fmt.Errorf("endpointstore: export boundary returned tenant %q for %q", event.TenantID, tenantID)
		}
		if err := enc.Encode(event); err != nil {
			return int64(i), err
		}
	}
	return int64(len(rows)), nil
}

// EnsureReaderRowPolicy constrains SELECTs by the per-request custom setting.
func (c *ClickHouse) EnsureReaderRowPolicy(ctx context.Context, readerUser string) error {
	if !chUserRe.MatchString(readerUser) {
		return fmt.Errorf("endpointstore: refusing malformed ClickHouse user identifier %q", readerUser)
	}
	query := chclient.ReaderRowPolicyDDL("probectl_endpoint_reader_scope", eventsTable, tenantSetting, readerUser)
	return c.execAt(ctx, "", query, nil, nil)
}

// Close releases no persistent client resources.
func (*ClickHouse) Close() error { return nil }

type endpointCHExec struct {
	store *ClickHouse
	base  string
}

func (e endpointCHExec) Exec(ctx context.Context, query string, params chmigrate.Params) error {
	return e.store.execAt(ctx, e.base, query, convertParams(params), nil)
}

func (e endpointCHExec) Query(ctx context.Context, query string, params chmigrate.Params) ([]map[string]any, error) {
	return e.store.queryAt(ctx, e.base, query+" FORMAT JSONEachRow", convertParams(params))
}

func convertParams(params chmigrate.Params) url.Values {
	out := url.Values{}
	for key, value := range params {
		out.Set("param_"+key, value)
	}
	return out
}

func boundParams(params map[string]string) url.Values {
	out := url.Values{}
	for key, value := range params {
		out.Set("param_"+key, value)
	}
	return out
}

func (c *ClickHouse) baseFor(routed string) string {
	if strings.TrimSpace(routed) != "" {
		return strings.TrimRight(routed, "/")
	}
	return c.base
}

func (c *ClickHouse) execAt(ctx context.Context, routed, query string, params url.Values, body io.Reader) error {
	endpoint := c.baseFor(routed) + "/?query=" + url.QueryEscape(query)
	if len(params) > 0 {
		endpoint += "&" + params.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, body)
	if err != nil {
		return err
	}
	resp, err := c.conn.Do(routed, req)
	if err != nil {
		return fmt.Errorf("endpointstore: request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		message, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("endpointstore: status %d: %s", resp.StatusCode, message)
	}
	return nil
}

func (c *ClickHouse) queryAt(ctx context.Context, routed, query string, params url.Values) ([]map[string]any, error) {
	endpoint := c.baseFor(routed) + "/?query=" + url.QueryEscape(query)
	if len(params) > 0 {
		endpoint += "&" + params.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.conn.Do(routed, req)
	if err != nil {
		return nil, fmt.Errorf("endpointstore: query: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		message, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("endpointstore: query status %d: %s", resp.StatusCode, message)
	}
	body, err := chclient.ReadResponseBody(resp.Body)
	if err != nil {
		return nil, err
	}
	return chclient.Decode(body)
}
