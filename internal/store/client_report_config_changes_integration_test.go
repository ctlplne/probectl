// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration || isolation

package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestClientReportConfigMonthKeepsCompletePredecessorsAndTenantScope(t *testing.T) {
	pool := setup(t.Context(), t)
	t.Cleanup(pool.Close)
	var tenants []string
	for lane := range 2 {
		tenant, err := NewTenants(pool).Create(t.Context(), fmt.Sprintf("config-month-%d-%d", time.Now().UnixNano(), lane), "config month")
		if err != nil {
			t.Fatal(err)
		}
		tenants = append(tenants, tenant.ID)
	}
	t.Cleanup(func() {
		if _, err := pool.Exec(context.Background(), `DELETE FROM tenants WHERE id=ANY($1::uuid[])`, tenants); err != nil {
			t.Error(err)
		}
	})
	from := time.Date(2024, 2, 1, 0, 0, 0, 0, time.UTC)
	to := from.AddDate(0, 1, 0)
	for lane, tenant := range tenants {
		inTenant(t.Context(), t, pool, tenant, func(ctx context.Context, sc tenancy.Scope) error {
			if _, err := sc.Q.Exec(ctx, `INSERT INTO device_configs(tenant_id,device,version,content,content_hash,previous_hash,drifted,observed_at,archived_at)
 SELECT $1,'same-device',n,'redacted modeled config',lpad(to_hex(n),64,'0'),CASE WHEN n>1 THEN lpad(to_hex(n-1),64,'0') ELSE '' END,n>1,
 CASE WHEN n=1 THEN $2::timestamptz-interval '1 day' ELSE $2::timestamptz+n*interval '1 second' END,$2
 FROM generate_series(1,1002) n`, tenant, from); err != nil {
				return err
			}
			// A predecessor in the other tenant cannot attest this drift even
			// when device, version and the claimed hashes match exactly.
			version, previous, drifted := 2000, "foreign-predecessor", true
			if lane == 1 {
				version, previous, drifted = 1999, "", false
			}
			_, err := sc.Q.Exec(ctx, `INSERT INTO device_configs(tenant_id,device,version,content,content_hash,previous_hash,drifted,observed_at,archived_at)
 VALUES($1,'same-device',$2,'redacted modeled config','foreign-predecessor',$3,$4,$5,$5)`, tenant, version, previous, drifted, from.Add(time.Hour))
			return err
		})
	}
	for lane, tenant := range tenants {
		inTenant(t.Context(), t, pool, tenant, func(ctx context.Context, sc tenancy.Scope) error {
			values, err := (ChangeEvents{}).ClientReportConfigChangesInScope(ctx, sc, from, to, 32<<20)
			if err != nil || len(values) != 1001 {
				t.Fatal("complete monthly archive changes were shortened or borrowed a foreign predecessor", len(values), err)
			}
			for index, value := range values {
				if value.TenantID != tenant || value.Config == nil || value.Config.CurrentVersion != index+2 || value.Config.PreviousVersion != index+1 || value.Config.CurrentID == value.Config.PreviousID || value.Config.PreviousID == "" || value.Config.PreviousHash == "" || value.OccurredAt.Before(from) || !value.OccurredAt.Before(to) {
					t.Fatal("projected change lost its exact tenant, predecessor or whole period", index)
				}
				if strings.Contains(value.Summary, "redacted modeled config") || len(value.Attributes) != 0 {
					t.Fatal("archive content entered change metadata")
				}
			}
			if values, err := (ChangeEvents{}).ClientReportConfigChangesInScope(ctx, sc, from, to, 8192); !errors.Is(err, ErrClientReportBudget) || values != nil {
				t.Fatal("under-admitted complete archive returned a prefix", err)
			}
			foreign := tenancy.WithTenant(ctx, tenancy.ID(tenants[1-lane]))
			if values, err := (ChangeEvents{}).ClientReportConfigChangesInScope(foreign, sc, from, to, 32<<20); !errors.Is(err, entity.ErrScopeMismatch) || values != nil {
				t.Fatal("foreign archive request borrowed the tenant transaction", err)
			}
			return nil
		})
	}
	// Source erasure removes its change evidence without disturbing the other
	// tenant's complete population. The predecessor itself predates the month.
	inTenant(t.Context(), t, pool, tenants[0], func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `UPDATE device_configs SET content='' WHERE tenant_id=$1 AND device='same-device' AND version=1`, tenants[0])
		return err
	})
	for lane, tenant := range tenants {
		inTenant(t.Context(), t, pool, tenant, func(ctx context.Context, sc tenancy.Scope) error {
			values, err := (ChangeEvents{}).ClientReportConfigChangesInScope(ctx, sc, from, to, 32<<20)
			if err != nil || len(values) != 1000+lane {
				t.Fatal("erased predecessor retained evidence or crossed tenant boundary", len(values), err)
			}
			return nil
		})
	}
	t.Log("real-integration: complete1001 configuration drifts per RLS tenant, exact predecessor outside report interval, foreign-predecessor refusal, full-memory refusal and erased-source sibling survival; archive rows/hashes modeled, not a collector or complete pack proof")
}
