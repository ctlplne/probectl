package chmigrate

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"
)

// fakeExec is an in-memory ClickHouse double: it records every statement and
// maintains the ledger rows that Query returns, including across "restarts".
type fakeExec struct {
	execed []string
	ledger []map[string]any
	failOn string // substring of a statement that should error
}

func (f *fakeExec) Exec(_ context.Context, sql string, p Params) error {
	if f.failOn != "" && strings.Contains(sql, f.failOn) {
		return errors.New("simulated clickhouse failure")
	}
	f.execed = append(f.execed, sql)
	if strings.HasPrefix(sql, "INSERT INTO "+Ledger) {
		// The SQL carries placeholders only — values arrive as BOUND params
		// (SEC-005/TENANT-108). A literal value in the SQL is a regression.
		if strings.Contains(sql, "VALUES ('") {
			return fmt.Errorf("fake: ledger insert carries literal values (must be bound): %q", sql)
		}
		v, _ := strconv.Atoi(p["version"])
		f.ledger = append(f.ledger, map[string]any{
			"component": p["component"], "version": float64(v), "name": p["name"], "checksum": p["checksum"],
		})
	}
	return nil
}

func (f *fakeExec) Query(_ context.Context, sql string, p Params) ([]map[string]any, error) {
	if f.failOn != "" && strings.Contains(sql, f.failOn) {
		return nil, errors.New("simulated clickhouse failure")
	}
	if strings.Contains(sql, "WHERE component =") && !strings.Contains(sql, "{component:String}") {
		return nil, fmt.Errorf("fake: component filter not bound: %q", sql)
	}
	var out []map[string]any
	for _, r := range f.ledger {
		if r["component"] == p["component"] {
			out = append(out, r)
		}
	}
	return out, nil
}

func twoMigrations() []Migration {
	return []Migration{
		{Version: 1, Name: "create_t", Statements: []string{
			"CREATE TABLE IF NOT EXISTS t (id UInt8) ENGINE = MergeTree ORDER BY id"}},
		{Version: 2, Name: "add_col", Statements: []string{
			"ALTER TABLE t ADD COLUMN IF NOT EXISTS a String",
			"ALTER TABLE t ADD COLUMN IF NOT EXISTS b String"}},
	}
}

func TestApplyFreshRunsInOrderAndRecords(t *testing.T) {
	db := &fakeExec{}
	done, err := Apply(context.Background(), db, "teststore", twoMigrations(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(done) != 2 || done[0] != 1 || done[1] != 2 {
		t.Fatalf("applied = %v, want [1 2]", done)
	}
	// Exact order: ledger DDL, v1 stmt, v1 record, v2 stmt 1, v2 stmt 2, v2 record.
	wantPrefixes := []string{
		"CREATE TABLE IF NOT EXISTS " + Ledger,
		"CREATE TABLE IF NOT EXISTS t",
		"INSERT INTO " + Ledger,
		"ALTER TABLE t ADD COLUMN IF NOT EXISTS a",
		"ALTER TABLE t ADD COLUMN IF NOT EXISTS b",
		"INSERT INTO " + Ledger,
	}
	if len(db.execed) != len(wantPrefixes) {
		t.Fatalf("executed %d statements, want %d:\n%s", len(db.execed), len(wantPrefixes), strings.Join(db.execed, "\n"))
	}
	for i, p := range wantPrefixes {
		if !strings.HasPrefix(db.execed[i], p) {
			t.Errorf("statement %d = %q, want prefix %q", i, db.execed[i], p)
		}
	}
	if len(db.ledger) != 2 {
		t.Fatalf("ledger rows = %v", db.ledger)
	}
}

func TestApplyIsIdempotentAcrossRestarts(t *testing.T) {
	db := &fakeExec{}
	if _, err := Apply(context.Background(), db, "teststore", twoMigrations(), nil); err != nil {
		t.Fatal(err)
	}
	before := len(db.execed)
	done, err := Apply(context.Background(), db, "teststore", twoMigrations(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(done) != 0 {
		t.Fatalf("second apply re-ran versions: %v", done)
	}
	// Only the ledger ensure runs again — no DDL, no ledger inserts.
	if got := db.execed[before:]; len(got) != 1 || !strings.HasPrefix(got[0], "CREATE TABLE IF NOT EXISTS "+Ledger) {
		t.Fatalf("second apply executed %v", got)
	}

	// A new pending version applies on top without touching the old ones.
	ms := append(twoMigrations(), Migration{Version: 3, Name: "add_c",
		Statements: []string{"ALTER TABLE t ADD COLUMN IF NOT EXISTS c String"}})
	done, err = Apply(context.Background(), db, "teststore", ms, nil)
	if err != nil || len(done) != 1 || done[0] != 3 {
		t.Fatalf("incremental apply = %v, %v", done, err)
	}
}

func TestComponentsAreIndependent(t *testing.T) {
	db := &fakeExec{}
	if _, err := Apply(context.Background(), db, "flowstore", twoMigrations(), nil); err != nil {
		t.Fatal(err)
	}
	done, err := Apply(context.Background(), db, "pathstore", twoMigrations()[:1], nil)
	if err != nil || len(done) != 1 {
		t.Fatalf("a second component must apply independently: %v, %v", done, err)
	}
}

func TestChecksumDriftRefuses(t *testing.T) {
	db := &fakeExec{}
	if _, err := Apply(context.Background(), db, "teststore", twoMigrations(), nil); err != nil {
		t.Fatal(err)
	}
	edited := twoMigrations()
	edited[1].Statements = []string{"ALTER TABLE t ADD COLUMN IF NOT EXISTS EVIL String"}
	_, err := Apply(context.Background(), db, "teststore", edited, nil)
	if err == nil || !strings.Contains(err.Error(), "CHECKSUM DRIFT") {
		t.Fatalf("an edited shipped version must refuse loudly, got %v", err)
	}
}

func TestStatementFailureStopsAndDoesNotRecord(t *testing.T) {
	db := &fakeExec{failOn: "ADD COLUMN IF NOT EXISTS a"}
	done, err := Apply(context.Background(), db, "teststore", twoMigrations(), nil)
	if err == nil || !strings.Contains(err.Error(), "0002_add_col statement 1") {
		t.Fatalf("want the failing version+statement in the error, got %v", err)
	}
	if len(done) != 1 || done[0] != 1 {
		t.Fatalf("v1 applied before the failure, got %v", done)
	}
	for _, r := range db.ledger {
		if r["version"].(float64) == 2 {
			t.Fatal("a failed version must not be recorded as applied")
		}
	}
}

func TestRegistryValidation(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name string
		comp string
		ms   []Migration
		want string
	}{
		{"empty component", "", twoMigrations(), "component name"},
		{"empty list", "x", nil, "empty migration list"},
		{"version zero", "x", []Migration{{Version: 0, Name: "n", Statements: []string{"s"}}}, "strictly ascending"},
		{"duplicate", "x", []Migration{
			{Version: 1, Name: "a", Statements: []string{"s"}},
			{Version: 1, Name: "b", Statements: []string{"s"}}}, "strictly ascending"},
		{"descending", "x", []Migration{
			{Version: 2, Name: "a", Statements: []string{"s"}},
			{Version: 1, Name: "b", Statements: []string{"s"}}}, "strictly ascending"},
		{"unnamed", "x", []Migration{{Version: 1, Statements: []string{"s"}}}, "no name"},
		{"no statements", "x", []Migration{{Version: 1, Name: "a"}}, "no statements"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db := &fakeExec{}
			if _, err := Apply(ctx, db, tc.comp, tc.ms, nil); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want error containing %q, got %v", tc.want, err)
			}
			if len(db.execed) != 0 {
				t.Fatal("an invalid registry must not touch the server")
			}
		})
	}
}

func TestChecksumCoversNameAndEveryStatement(t *testing.T) {
	m := Migration{Version: 1, Name: "a", Statements: []string{"s1", "s2"}}
	base := Checksum(m)
	renamed := m
	renamed.Name = "b"
	reordered := m
	reordered.Statements = []string{"s2", "s1"}
	if Checksum(renamed) == base || Checksum(reordered) == base {
		t.Fatal("checksum must cover the name and statement order")
	}
}
