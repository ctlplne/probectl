// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

// Command upgradefixture plants and verifies a tiny two-tenant lifecycle
// sentinel around the v0.5.0 -> current -> v0.5.0 rollback drill. It is test
// tooling only: values are synthetic and key bytes are explicitly not secrets.
package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	tenantA = "10000000-0000-0000-0000-000000000001"
	tenantB = "20000000-0000-0000-0000-000000000002"
	testA   = "10000000-0000-0000-0000-000000000011"
	testB   = "20000000-0000-0000-0000-000000000022"
)

type snapshot struct {
	Tenants []tenantRow `json:"tenants"`
	Tests   []testRow   `json:"tests"`
	Keys    []keyRow    `json:"keys"`
	Audit   []auditRow  `json:"audit"`
}

type tenantRow struct {
	ID     string `json:"id"`
	Slug   string `json:"slug"`
	Name   string `json:"name"`
	Status string `json:"status"`
}

type testRow struct {
	ID       string `json:"id"`
	TenantID string `json:"tenant_id"`
	Name     string `json:"name"`
	Type     string `json:"type"`
	Target   string `json:"target"`
	Enabled  bool   `json:"enabled"`
}

type keyRow struct {
	TenantID   string `json:"tenant_id"`
	Version    int    `json:"version"`
	Mode       string `json:"mode"`
	State      string `json:"state"`
	WrappedKEK string `json:"wrapped_kek_hex"`
}

type auditRow struct {
	TenantID string `json:"tenant_id"`
	Seq      int64  `json:"seq"`
	Actor    string `json:"actor"`
	Action   string `json:"action"`
	Hash     string `json:"hash"`
}

func main() {
	mode := flag.String("mode", "verify", "seed or verify")
	expected := flag.String("expected", "", "expected fixture SHA-256 for verify")
	flag.Parse()
	dsn := strings.TrimSpace(os.Getenv("PROBECTL_DATABASE_URL"))
	if dsn == "" {
		fatalf("PROBECTL_DATABASE_URL is required")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		fatalf("connect: %v", err)
	}
	defer pool.Close()

	switch *mode {
	case "seed":
		if err := seed(ctx, pool); err != nil {
			fatalf("seed: %v", err)
		}
	case "verify":
		if *expected == "" {
			fatalf("-expected is required in verify mode")
		}
	default:
		fatalf("unsupported mode %q", *mode)
	}

	digest, err := fixtureDigest(ctx, pool)
	if err != nil {
		fatalf("snapshot: %v", err)
	}
	if *mode == "verify" {
		if digest != *expected {
			fatalf("fixture digest changed: got %s want %s", digest, *expected)
		}
		if err := verifyIsolationAndContinuity(ctx, pool); err != nil {
			fatalf("guardrails: %v", err)
		}
	}
	var migrationCount, migrationMax int
	if err := pool.QueryRow(ctx, `SELECT count(*),COALESCE(max(version),0) FROM schema_migrations`).Scan(&migrationCount, &migrationMax); err != nil {
		fatalf("migration ledger: %v", err)
	}
	fmt.Printf("UPGRADE_FIXTURE mode=%s digest=%s tenants=2 tests=2 keys=2 audit_events=2 migrations=%d migration_max=%d\n", *mode, digest, migrationCount, migrationMax)
}

func seed(ctx context.Context, pool *pgxpool.Pool) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck -- commit below is authoritative
	for _, row := range []struct{ id, slug, name string }{
		{tenantA, "upgrade-a", "Upgrade tenant A"},
		{tenantB, "upgrade-b", "Upgrade tenant B"},
	} {
		if _, err := tx.Exec(ctx, `INSERT INTO tenants(id,slug,name,status) VALUES($1,$2,$3,'active') ON CONFLICT (id) DO NOTHING`, row.id, row.slug, row.name); err != nil {
			return err
		}
	}
	for _, row := range []struct{ id, tenant, name, target string }{
		{testA, tenantA, "edge-dns", "192.0.2.10"},
		{testB, tenantB, "edge-dns", "192.0.2.10"},
	} {
		if _, err := tx.Exec(ctx, `INSERT INTO tests(id,tenant_id,name,type,target,enabled) VALUES($1,$2,$3,'dns',$4,true) ON CONFLICT (id) DO NOTHING`, row.id, row.tenant, row.name, row.target); err != nil {
			return err
		}
	}
	for _, tenant := range []string{tenantA, tenantB} {
		wrapped := []byte("synthetic-wrapped-kek:" + tenant)
		if _, err := tx.Exec(ctx, `INSERT INTO tenant_keys(tenant_id,version,mode,state,wrapped_kek) VALUES($1,1,'managed','active',$2) ON CONFLICT (tenant_id,version) DO NOTHING`, tenant, wrapped); err != nil {
			return err
		}
		h := crypto.Hash([]byte("upgrade-audit:" + tenant))
		if _, err := tx.Exec(ctx, `INSERT INTO audit_events(tenant_id,seq,actor,action,target,data,prev_hash,hash) VALUES($1,1,'upgrade-drill','upgrade.fixture','synthetic','{}','','`+hex.EncodeToString(h)+`') ON CONFLICT (tenant_id,seq) DO NOTHING`, tenant); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func fixtureDigest(ctx context.Context, pool *pgxpool.Pool) (string, error) {
	var s snapshot
	rows, err := pool.Query(ctx, `SELECT id::text,slug,name,status FROM tenants WHERE id = ANY($1::uuid[]) ORDER BY id`, []string{tenantA, tenantB})
	if err != nil {
		return "", err
	}
	for rows.Next() {
		var r tenantRow
		if err := rows.Scan(&r.ID, &r.Slug, &r.Name, &r.Status); err != nil {
			rows.Close()
			return "", err
		}
		s.Tenants = append(s.Tenants, r)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return "", err
	}
	rows.Close()

	rows, err = pool.Query(ctx, `SELECT id::text,tenant_id::text,name,type,target,enabled FROM tests WHERE tenant_id = ANY($1::uuid[]) ORDER BY tenant_id,id`, []string{tenantA, tenantB})
	if err != nil {
		return "", err
	}
	for rows.Next() {
		var r testRow
		if err := rows.Scan(&r.ID, &r.TenantID, &r.Name, &r.Type, &r.Target, &r.Enabled); err != nil {
			rows.Close()
			return "", err
		}
		s.Tests = append(s.Tests, r)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return "", err
	}
	rows.Close()

	rows, err = pool.Query(ctx, `SELECT tenant_id::text,version,mode,state,encode(wrapped_kek,'hex') FROM tenant_keys WHERE tenant_id = ANY($1::uuid[]) ORDER BY tenant_id,version`, []string{tenantA, tenantB})
	if err != nil {
		return "", err
	}
	for rows.Next() {
		var r keyRow
		if err := rows.Scan(&r.TenantID, &r.Version, &r.Mode, &r.State, &r.WrappedKEK); err != nil {
			rows.Close()
			return "", err
		}
		s.Keys = append(s.Keys, r)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return "", err
	}
	rows.Close()

	rows, err = pool.Query(ctx, `SELECT tenant_id::text,seq,actor,action,hash FROM audit_events WHERE tenant_id = ANY($1::uuid[]) ORDER BY tenant_id,seq`, []string{tenantA, tenantB})
	if err != nil {
		return "", err
	}
	for rows.Next() {
		var r auditRow
		if err := rows.Scan(&r.TenantID, &r.Seq, &r.Actor, &r.Action, &r.Hash); err != nil {
			rows.Close()
			return "", err
		}
		s.Audit = append(s.Audit, r)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return "", err
	}
	rows.Close()

	if len(s.Tenants) != 2 || len(s.Tests) != 2 || len(s.Keys) != 2 || len(s.Audit) != 2 {
		return "", fmt.Errorf("incomplete fixture: tenants=%d tests=%d keys=%d audit=%d", len(s.Tenants), len(s.Tests), len(s.Keys), len(s.Audit))
	}
	raw, err := json.Marshal(s)
	if err != nil {
		return "", err
	}
	sum := crypto.Hash(raw)
	return hex.EncodeToString(sum), nil
}

func verifyIsolationAndContinuity(ctx context.Context, pool *pgxpool.Pool) error {
	for _, tc := range []struct {
		tenant string
		want   string
	}{
		{tenantA, testA},
		{tenantB, testB},
	} {
		ids, err := tenantVisibleTests(ctx, pool, tc.tenant)
		if err != nil {
			return err
		}
		if len(ids) != 1 || ids[0] != tc.want {
			return fmt.Errorf("tenant %s saw tests %v, want only %s", tc.tenant, ids, tc.want)
		}
	}
	ids, err := tenantVisibleTests(ctx, pool, "")
	if err != nil {
		return err
	}
	if len(ids) != 0 {
		return fmt.Errorf("unbound app role saw tests %v", ids)
	}
	var headsExist bool
	if err := pool.QueryRow(ctx, `SELECT to_regclass('public.audit_stream_heads') IS NOT NULL`).Scan(&headsExist); err != nil {
		return err
	}
	if !headsExist {
		// v0.5.0 predates the durable head table. The fixture digest above still
		// verifies the source audit row; migration 0075 creates/backfills the
		// head during the upgrade and the check below becomes mandatory.
		return nil
	}
	var bad int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_stream_heads h JOIN audit_events e USING (tenant_id) WHERE h.tenant_id = ANY($1::uuid[]) AND (h.head_seq <> e.seq OR h.head_hash <> e.hash)`, []string{tenantA, tenantB}).Scan(&bad); err != nil {
		return err
	}
	if bad != 0 {
		return fmt.Errorf("%d audit stream heads lost continuity", bad)
	}
	return nil
}

func tenantVisibleTests(ctx context.Context, pool *pgxpool.Pool, tenant string) ([]string, error) {
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck -- read-only cleanup
	if _, err := tx.Exec(ctx, `SET LOCAL ROLE probectl_app`); err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx, `SELECT set_config('probectl.tenant_id',$1,true)`, tenant); err != nil {
		return nil, err
	}
	rows, err := tx.Query(ctx, `SELECT id::text FROM tests ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids, rows.Err()
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "probectl-upgrade-fixture: "+format+"\n", args...)
	os.Exit(1)
}
