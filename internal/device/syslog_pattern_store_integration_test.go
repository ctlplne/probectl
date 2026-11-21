// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package device_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/device"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/migrate"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport"
	"github.com/ctlplne/probectl/migrations"
)

func TestSyslogPatternCountsKeepTenantAndOriginalWindow(t *testing.T) {
	dbURL := os.Getenv("PROBECTL_DATABASE_URL")
	if dbURL == "" {
		testsupport.SkipOrFatal(t, "set PROBECTL_DATABASE_URL for the tenant-owned syslog pattern test")
	}
	pool, err := pgxpool.New(t.Context(), dbURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	if err := pool.Ping(t.Context()); err != nil {
		testsupport.SkipOrFatal(t, "database unavailable: %v", err)
	}
	if _, err := migrate.New(migrations.FS, nil).Apply(t.Context(), pool); err != nil {
		t.Fatal(err)
	}
	st := device.NewPostgresOpsStore(pool)
	tenants, owners := store.NewTenants(pool), [2]store.Tenant{}
	left := time.Now().UTC().Truncate(time.Minute)
	input := device.SyslogPatternSelection{Device: "overlapping-edge", From: left, To: left.Add(time.Minute), Limit: 5, MaxInputRows: 20}
	ids := [2]string{}
	for lane := range owners {
		owner, err := tenants.Create(t.Context(), fmt.Sprintf("patterns-%d-%d", lane, time.Now().UnixNano()), "Syslog operator")
		if err != nil {
			t.Fatal(err)
		}
		owners[lane] = *owner
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(owner.ID))
		for index := range lane + 1 {
			event, err := st.RecordSyslog(ctx, device.SyslogEvent{TenantID: owner.ID, Device: input.Device,
				ObservedAt: left.Add(time.Duration(10-index) * time.Second), AppName: "monitor",
				Message: fmt.Sprintf("node 192.0.2.%d counted %d errors", index+1, index+3)})
			if err != nil || ids[lane] != "" && event.PatternID != ids[lane] || event.PatternVersion != 1 {
				t.Fatal("authored variable fields changed the stored pattern key", event.PatternID, err)
			}
			ids[lane] = event.PatternID
		}
		_, err = st.RecordSyslog(ctx, device.SyslogEvent{TenantID: owner.ID, Device: input.Device,
			ObservedAt: input.To, AppName: "monitor", Message: "node 192.0.2.12 counted 11 errors"})
		if err != nil {
			t.Fatal(err)
		}
	}
	if ids[0] == ids[1] {
		t.Fatal("identical structures have comparable keys across tenants")
	}
	first := tenancy.WithTenant(t.Context(), tenancy.ID(owners[0].ID))
	if err := tenancy.InTenant(first, pool, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, "INSERT INTO device_syslog(tenant_id,device,observed_at,message) VALUES ($1,$2,$3,$4)",
			sc.Tenant.String(), input.Device, left.Add(15*time.Second), "legacy observation")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	reader := device.NewPostgresOpsStore(pool)
	for lane, owner := range owners {
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(owner.ID))
		got, err := reader.ListSyslogPatterns(ctx, owner.ID, input)
		if err != nil || got.IndexedRows != int64(lane+1) || got.UnindexedRows != int64(1-lane) ||
			got.TotalPatterns != 1 || len(got.Patterns) != 1 {
			t.Fatal("pattern counts crossed scope, discarded legacy coverage, or included the right boundary", got, err)
		}
		item := got.Patterns[0]
		if item.ID != ids[lane] || item.Count != int64(lane+1) || item.Kind != device.SyslogPatternOther ||
			!item.FirstAt.Equal(left.Add(time.Duration(10-lane)*time.Second)) || !item.LastAt.Equal(left.Add(10*time.Second)) {
			t.Fatal("the reader changed the original count or clock", item)
		}
	}
	if got, err := reader.ListSyslogPatterns(first, owners[1].ID, input); !errors.Is(err, tenancy.ErrNoTenant) || len(got.Patterns) != 0 {
		t.Fatal("a tenant request read sibling scope", got, err)
	}
	input.MaxInputRows = 1
	if got, err := reader.ListSyslogPatterns(first, owners[0].ID, input); !errors.Is(err, device.ErrSyslogPatternBudget) || got.IndexedRows != 0 {
		t.Fatal("the reader exposed a partial count after input budget refusal", got, err)
	}
}
