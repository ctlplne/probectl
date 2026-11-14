// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package migrate_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/store/migrate"
	"github.com/ctlplne/probectl/internal/testsupport"
)

func TestDeviceConfigBindingUpgradePreservesLegacyAndStagesOnlineConstraints(t *testing.T) {
	ctx := t.Context()
	cfg, err := pgxpool.ParseConfig(dsn())
	if err != nil {
		t.Fatal(err)
	}
	adminCfg := cfg.Copy()
	adminCfg.ConnConfig.Database = "postgres"
	admin, err := pgxpool.NewWithConfig(ctx, adminCfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(admin.Close)
	if err := admin.Ping(ctx); err != nil {
		testsupport.SkipOrFatal(t, "migration database unavailable: %v", err)
	}
	name := fmt.Sprintf("probectl-qa-beta-config-%d", time.Now().UnixNano())
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+quoteIdent(name)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := admin.Exec(context.Background(), "DROP DATABASE "+quoteIdent(name)); err != nil {
			t.Error("remove owned migration database", err)
		}
	})
	cfg.ConnConfig.Database = name
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	if _, err := migrate.New(migrationsThrough(t, 211), nil).Apply(ctx, pool); err != nil {
		t.Fatal(err)
	}
	for _, tenant := range []string{migrationTenantA, migrationTenantB} {
		if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,slug,name) VALUES($1::uuid,$1::text,$1::text)`, tenant); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `INSERT INTO device_configs(tenant_id,device,version,content,content_hash) VALUES($1,'same-device',1,$2,$2)`, tenant, "retained-"+tenant); err != nil {
			t.Fatal(err)
		}
	}
	if got, err := migrate.New(migrationsThrough(t, 214), nil).Apply(ctx, pool); err != nil || len(got) != 3 {
		t.Fatal("fresh upgrade did not execute all three new migrations", got, err)
	}
	for _, tenant := range []string{migrationTenantA, migrationTenantB} {
		if got := tenantVisibleCount(ctx, t, pool, tenant, "device_configs", "content=$1 AND entity_context_id IS NULL", "retained-"+tenant); got != 1 {
			t.Fatal("upgrade lost or crossed a tenant's original archive", tenant, got)
		}
	}
	var indexes, constraints int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM pg_index i JOIN pg_class c ON c.oid=i.indexrelid WHERE i.indrelid='device_configs'::regclass AND i.indisvalid AND c.relname IN ('device_configs_bound_stream_version_idx','device_configs_legacy_stream_version_idx','device_configs_bound_observed_idx')`).Scan(&indexes); err != nil || indexes != 3 {
		t.Fatal("archive replacement indexes are not valid", indexes, err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM pg_constraint WHERE conrelid='device_configs'::regclass AND convalidated AND conname IN ('device_configs_binding_complete','device_configs_binding_device_fk')`).Scan(&constraints); err != nil || constraints != 2 {
		t.Fatal("archive constraints were not validated after online construction", constraints, err)
	}
	if got, err := migrate.New(migrationsThrough(t, 214), nil).Apply(ctx, pool); err != nil || len(got) != 0 {
		t.Fatal("archive upgrade is not idempotent", got, err)
	}
}
