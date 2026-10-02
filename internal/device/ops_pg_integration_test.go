// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package device_test

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/device"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/migrate"
	"github.com/ctlplne/probectl/internal/testsupport"
	"github.com/ctlplne/probectl/migrations"
)

// TestPostgresOpsStorePersistsAndIsolates is the PLAT-06/RTP-08/WEB-26
// regression. Device syslog and config archive were process-memory only — lost
// on restart and not shared between replicas. The Postgres-backed store must
// persist them (a fresh store instance — a restart / second replica — sees the
// rows) and isolate them per tenant via FORCE RLS.
func TestPostgresOpsStorePersistsAndIsolates(t *testing.T) {
	url := os.Getenv("PROBECTL_DATABASE_URL")
	if url == "" {
		testsupport.SkipOrFatal(t, "PROBECTL_DATABASE_URL not set — device-ops durability gate runs in CI")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		testsupport.SkipOrFatal(t, "no database available: %v", err)
	}
	if _, err := migrate.New(migrations.FS, nil).Apply(ctx, pool); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}

	tenants := store.NewTenants(pool)
	tnA, err := tenants.Create(ctx, fmt.Sprintf("devops-a-%d", time.Now().UnixNano()), "DevOps A")
	if err != nil {
		t.Fatalf("create tenant A: %v", err)
	}
	tnB, err := tenants.Create(ctx, fmt.Sprintf("devops-b-%d", time.Now().UnixNano()), "DevOps B")
	if err != nil {
		t.Fatalf("create tenant B: %v", err)
	}

	s := device.NewPostgresOpsStore(pool)
	const secret = "$1$abcd$EncLocalHash"
	v1, err := s.ArchiveConfig(ctx, device.ConfigVersion{TenantID: tnA.ID, Device: "r1", Content: "hostname r1\nenable secret 5 " + secret + "\n"})
	if err != nil {
		t.Fatalf("archive v1: %v", err)
	}
	if v1.Version != 1 || v1.Drifted {
		t.Fatalf("first archive: version=%d drifted=%v, want 1/false", v1.Version, v1.Drifted)
	}
	if strings.Contains(v1.Content, secret) {
		t.Errorf("WEB-03/PLAT-06: the archived config kept a secret in clear: %q", v1.Content)
	}
	v2, err := s.ArchiveConfig(ctx, device.ConfigVersion{TenantID: tnA.ID, Device: "r1", Content: "hostname r1\nno shutdown\n"})
	if err != nil {
		t.Fatalf("archive v2: %v", err)
	}
	if v2.Version != 2 || !v2.Drifted || v2.PreviousHash != v1.ContentHash {
		t.Fatalf("second archive: version=%d drifted=%v prev=%q, want 2/true/%q", v2.Version, v2.Drifted, v2.PreviousHash, v1.ContentHash)
	}
	if _, err := s.RecordSyslog(ctx, device.SyslogEvent{TenantID: tnA.ID, Device: "r1", Severity: 3, Message: "link down"}); err != nil {
		t.Fatalf("record syslog: %v", err)
	}

	// "Restart" / second replica: a brand-new store over the same database.
	s2 := device.NewPostgresOpsStore(pool)
	cfgs, err := s2.ListConfigs(ctx, tnA.ID, device.OpsFilter{})
	if err != nil {
		t.Fatalf("list configs after restart: %v", err)
	}
	if len(cfgs) != 2 {
		t.Fatalf("PLAT-06: configs did not survive restart: got %d, want 2", len(cfgs))
	}
	logs, err := s2.ListSyslog(ctx, tnA.ID, device.OpsFilter{})
	if err != nil {
		t.Fatalf("list syslog after restart: %v", err)
	}
	if len(logs) != 1 {
		t.Fatalf("RTP-08: syslog did not survive restart: got %d, want 1", len(logs))
	}

	// Isolation: tenant B sees none of tenant A's rows (FORCE RLS).
	if got, _ := s2.ListConfigs(ctx, tnB.ID, device.OpsFilter{}); len(got) != 0 {
		t.Errorf("isolation: tenant B sees %d of tenant A's configs, want 0", len(got))
	}
	if got, _ := s2.ListSyslog(ctx, tnB.ID, device.OpsFilter{}); len(got) != 0 {
		t.Errorf("isolation: tenant B sees %d of tenant A's syslog, want 0", len(got))
	}
}
