//go:build isolation

package chmigrate

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

// httpExec is a minimal ClickHouse HTTP adapter for the containerized gate
// (the ci cross-tenant-isolation job provides the server).
type httpExec struct {
	base   string
	client *http.Client
}

func paramsQS(p Params) string {
	var sb strings.Builder
	for k, v := range p {
		sb.WriteString("&param_")
		sb.WriteString(url.QueryEscape(k))
		sb.WriteString("=")
		sb.WriteString(url.QueryEscape(v))
	}
	return sb.String()
}

func (h httpExec) Exec(ctx context.Context, sql string, p Params) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.base+"/?query="+url.QueryEscape(sql)+paramsQS(p), nil)
	if err != nil {
		return err
	}
	resp, err := h.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("clickhouse status %d: %s", resp.StatusCode, b)
	}
	return nil
}

func (h httpExec) Query(ctx context.Context, sql string, p Params) ([]map[string]any, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		h.base+"/?query="+url.QueryEscape(sql+" FORMAT JSONEachRow")+paramsQS(p), nil)
	if err != nil {
		return nil, err
	}
	resp, err := h.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("clickhouse status %d: %s", resp.StatusCode, body)
	}
	var rows []map[string]any
	for _, line := range bytes.Split(body, []byte("\n")) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var row map[string]any
		if err := json.Unmarshal(line, &row); err != nil {
			return nil, err
		}
		rows = append(rows, row)
	}
	return rows, nil
}

// U-046 against real ClickHouse: fresh apply creates the schema and records
// the ledger; re-apply is a no-op; an edited shipped version refuses.
func TestClickHouseMigrationsEndToEnd(t *testing.T) {
	base := os.Getenv("PROBECTL_FLOWSTORE_URL")
	if base == "" {
		t.Skip("PROBECTL_FLOWSTORE_URL not set — the CH migration gate runs in CI")
	}
	db := httpExec{base: strings.TrimRight(base, "/"), client: &http.Client{Timeout: 30 * time.Second}}
	ctx := context.Background()

	nano := time.Now().UnixNano()
	comp := fmt.Sprintf("migtest-%d", nano)
	table := fmt.Sprintf("probectl_migtest_%d", nano)
	ms := []Migration{
		{Version: 1, Name: "create", Statements: []string{
			"CREATE TABLE IF NOT EXISTS " + table + " (id UInt8) ENGINE = MergeTree ORDER BY id"}},
		{Version: 2, Name: "widen", Statements: []string{
			"ALTER TABLE " + table + " ADD COLUMN IF NOT EXISTS note String"}},
	}
	t.Cleanup(func() {
		_ = db.Exec(ctx, "DROP TABLE IF EXISTS "+table, nil)
		_ = db.Exec(ctx, "DELETE FROM "+Ledger+" WHERE component = {component:String}", Params{"component": comp})
	})

	done, err := Apply(ctx, db, comp, ms, nil)
	if err != nil {
		t.Fatalf("fresh apply: %v", err)
	}
	if len(done) != 2 || done[0] != 1 || done[1] != 2 {
		t.Fatalf("applied = %v, want [1 2]", done)
	}

	// The schema really exists (v1 table + v2 column).
	cols, err := db.Query(ctx,
		"SELECT name FROM system.columns WHERE table = {table:String} AND name = 'note'",
		Params{"table": table})
	if err != nil || len(cols) != 1 {
		t.Fatalf("migrated schema missing on the server: cols=%v err=%v", cols, err)
	}
	// The ledger is recorded server-side with matching checksums.
	rows, err := db.Query(ctx, "SELECT version, checksum FROM "+Ledger+
		" FINAL WHERE component = {component:String} ORDER BY version", Params{"component": comp})
	if err != nil || len(rows) != 2 {
		t.Fatalf("ledger rows = %v err=%v", rows, err)
	}
	for i, m := range ms {
		if got := anyToString(rows[i]["checksum"]); got != Checksum(m) {
			t.Fatalf("ledger checksum for v%d = %s, want %s", m.Version, got, Checksum(m))
		}
	}

	// Re-apply: a clean no-op.
	if done, err = Apply(ctx, db, comp, ms, nil); err != nil || len(done) != 0 {
		t.Fatalf("re-apply must be a no-op, got %v err=%v", done, err)
	}

	// An edited shipped version refuses loudly.
	edited := []Migration{ms[0], {Version: 2, Name: "widen", Statements: []string{
		"ALTER TABLE " + table + " ADD COLUMN IF NOT EXISTS evil String"}}}
	if _, err := Apply(ctx, db, comp, edited, nil); err == nil || !strings.Contains(err.Error(), "CHECKSUM DRIFT") {
		t.Fatalf("edited shipped version must refuse, got %v", err)
	}
}
