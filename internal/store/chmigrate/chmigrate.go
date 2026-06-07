// Package chmigrate is the ClickHouse counterpart of internal/store/migrate
// (U-046): versioned, ordered schema migrations recorded in a server-side
// ledger (probectl_ch_migrations), replacing inline one-shot DDL strings.
// Each store component (flowstore, pathstore, ...) owns its migration list —
// stores may point at different ClickHouse instances, so the ledger is keyed
// by (component, version) and lives on whichever server the component uses.
//
// ClickHouse offers neither advisory locks nor transactional DDL, so the
// Postgres runner's session lock cannot be mirrored literally. The same
// guarantees are reached differently:
//
//  1. ordered: versions are strictly ascending and applied in order; a
//     duplicate or out-of-order registry refuses to run at all;
//  2. recorded: every applied version lands in the ledger with a checksum
//     and timestamp — auditable on the server, exactly like
//     schema_migrations in Postgres;
//  3. safe under concurrency: every statement must be idempotent
//     (IF NOT EXISTS / additive), so concurrent appliers converge, and the
//     ledger is a ReplacingMergeTree keyed by (component, version), so a
//     double-record collapses to one row;
//  4. no silent drift: a recorded version whose statements have since
//     changed fails the apply loudly (checksum mismatch) — shipped versions
//     are immutable; schema changes are NEW versions.
package chmigrate

import (
	"context"
	"encoding/hex"
	"fmt"
	"log/slog"
	"strconv"
	"strings"

	"github.com/imfeelingtheagi/probectl/internal/crypto"
)

// Exec is the minimal ClickHouse client surface the runner needs — the
// stores' HTTP adapters implement it.
// Params carries SERVER-BOUND values for {name:Type} placeholders (the
// ClickHouse HTTP param_* mechanism) — values never enter the SQL text
// (SEC-005/TENANT-108). nil = a statement with no bound values (DDL).
type Params map[string]string

type Exec interface {
	Exec(ctx context.Context, sql string, params Params) error
	Query(ctx context.Context, sql string, params Params) ([]map[string]any, error)
}

// Migration is one versioned schema step. Statements run in order, one HTTP
// request each (the ClickHouse HTTP interface takes one statement per call).
// Every statement MUST be idempotent (IF NOT EXISTS / additive ALTER).
type Migration struct {
	Version    int
	Name       string
	Statements []string
}

// Ledger is the migration ledger table, mirroring schema_migrations.
const Ledger = "probectl_ch_migrations"

const ledgerDDL = `CREATE TABLE IF NOT EXISTS ` + Ledger + ` (
  component String,
  version UInt32,
  name String,
  checksum String,
  applied_at DateTime64(3) DEFAULT now64(3)
) ENGINE = ReplacingMergeTree
ORDER BY (component, version)`

// Checksum fingerprints a migration's content (name + statements) through
// internal/crypto (guardrail 3). The ledger stores it; Apply enforces it.
func Checksum(m Migration) string {
	payload := m.Name + "\x00" + strings.Join(m.Statements, "\x00")
	return hex.EncodeToString(crypto.Hash([]byte(payload)))
}

// Apply runs every migration not yet recorded for component, in version
// order, and records each in the ledger. It returns the versions applied in
// this call — empty when the schema is already up to date. A recorded
// version whose checksum no longer matches the code refuses loudly.
func Apply(ctx context.Context, db Exec, component string, ms []Migration, log *slog.Logger) ([]int, error) {
	if log == nil {
		log = slog.Default()
	}
	if err := validate(component, ms); err != nil {
		return nil, err
	}
	if err := db.Exec(ctx, ledgerDDL, nil); err != nil {
		return nil, fmt.Errorf("chmigrate: ensure ledger: %w", err)
	}
	rows, err := db.Query(ctx,
		"SELECT version, checksum FROM "+Ledger+" FINAL WHERE component = {component:String}",
		Params{"component": component})
	if err != nil {
		return nil, fmt.Errorf("chmigrate: read ledger: %w", err)
	}
	recorded := make(map[int]string, len(rows))
	for _, r := range rows {
		recorded[anyToInt(r["version"])] = anyToString(r["checksum"])
	}

	var done []int
	for _, m := range ms {
		sum := Checksum(m)
		if got, ok := recorded[m.Version]; ok {
			if got != sum {
				return done, fmt.Errorf(
					"chmigrate: %s migration %04d_%s CHECKSUM DRIFT (ledger %s, code %s) — shipped versions are immutable; add a new version instead of editing this one",
					component, m.Version, m.Name, got, sum)
			}
			continue
		}
		for i, stmt := range m.Statements {
			if err := db.Exec(ctx, stmt, nil); err != nil {
				return done, fmt.Errorf("chmigrate: %s migration %04d_%s statement %d: %w",
					component, m.Version, m.Name, i+1, err)
			}
		}
		record := "INSERT INTO " + Ledger +
			" (component, version, name, checksum) VALUES ({component:String}, {version:UInt32}, {name:String}, {checksum:String})"
		if err := db.Exec(ctx, record, Params{
			"component": component, "version": strconv.Itoa(m.Version),
			"name": m.Name, "checksum": sum,
		}); err != nil {
			return done, fmt.Errorf("chmigrate: record %s %04d_%s in the ledger: %w", component, m.Version, m.Name, err)
		}
		log.Info("applied clickhouse migration", "component", component, "version", m.Version, "name", m.Name)
		done = append(done, m.Version)
	}
	return done, nil
}

// validate enforces the registry shape before anything touches the server.
func validate(component string, ms []Migration) error {
	if component == "" {
		return fmt.Errorf("chmigrate: a component name is required")
	}
	if len(ms) == 0 {
		return fmt.Errorf("chmigrate: %s: empty migration list", component)
	}
	prev := 0
	for i, m := range ms {
		if m.Version <= prev {
			return fmt.Errorf("chmigrate: %s: versions must be strictly ascending and ≥ 1 (position %d has %d after %d)",
				component, i, m.Version, prev)
		}
		if m.Name == "" {
			return fmt.Errorf("chmigrate: %s: migration %d has no name", component, m.Version)
		}
		if len(m.Statements) == 0 {
			return fmt.Errorf("chmigrate: %s: migration %04d_%s has no statements", component, m.Version, m.Name)
		}
		prev = m.Version
	}
	return nil
}

// sqlStr renders a ClickHouse string literal with the necessary escaping.
func anyToInt(v any) int {
	switch n := v.(type) {
	case float64:
		return int(n)
	case string:
		i, _ := strconv.Atoi(n)
		return i
	}
	return 0
}

func anyToString(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}
