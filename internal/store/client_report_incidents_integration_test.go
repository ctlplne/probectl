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
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestClientReportIncidentMonthKeepsCompletePopulationAndTenantScope(t *testing.T) {
	pool := setup(t.Context(), t)
	t.Cleanup(pool.Close)
	var tenants []string
	for lane := range 2 {
		tenant, err := NewTenants(pool).Create(t.Context(), fmt.Sprintf("client-month-%d-%d", time.Now().UnixNano(), lane), "client month")
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
	contextID, entityID := uuid.NewString(), uuid.NewString()
	retainedIDs := map[string]string{}
	for _, tenant := range tenants {
		retainedID := uuid.NewString()
		retainedIDs[tenant] = retainedID
		inTenant(t.Context(), t, pool, tenant, func(ctx context.Context, sc tenancy.Scope) error {
			if _, err := sc.Q.Exec(ctx, `INSERT INTO entity_contexts
 (tenant_id,id,site_id,vrf_id,site_label,vrf_label) VALUES($1,$2,$3,$4,'client month','client month')`, tenant, contextID, uuid.NewString(), uuid.NewString()); err != nil {
				return err
			}
			if _, err := sc.Q.Exec(ctx, `INSERT INTO entities(tenant_id,context_id,id,kind,label)
 VALUES($1,$2,$3,'device','client month')`, tenant, contextID, entityID); err != nil {
				return err
			}
			if _, err := sc.Q.Exec(ctx, `INSERT INTO incidents(tenant_id,title,started_at,last_seen_at,resolved_at,status)
 SELECT $1,'monthly-' || n::text,$2::timestamptz+n*interval '1 second',
 $2::timestamptz+n*interval '1 second',$2::timestamptz+n*interval '1 second','resolved'
 FROM generate_series(1,1001) n`, tenant, from); err != nil {
				return err
			}
			if _, err := sc.Q.Exec(ctx, `INSERT INTO incidents
 (tenant_id,id,title,started_at,last_seen_at,resolved_at,status,entity_context_id,entity_id,identity_lookup_attempted)
 VALUES($1,$2,'straddles month',$3::timestamptz-interval '1 day',$3,$3::timestamptz+interval '1 day','resolved',$4,$5,true)`, tenant, retainedID, from, contextID, entityID); err != nil {
				return err
			}
			if _, err := sc.Q.Exec(ctx, `INSERT INTO incidents(tenant_id,title,started_at,last_seen_at,resolved_at,status) VALUES
 ($1,'ends exactly before month',$2::timestamptz-interval '1 day',$2,$2,'resolved'),
 ($1,'starts next month',$3,$3,NULL,'open'),
	($1,'instant at month start',$2,$2,$2,'resolved')`, tenant, from, to); err != nil {
				return err
			}
			if _, err := sc.Q.Exec(ctx, `INSERT INTO change_events(tenant_id,title,summary,attributes,occurred_at)
 SELECT $1,'monthly-' || n::text,CASE WHEN n=42 THEN repeat('完整',1000) ELSE '' END,
 jsonb_build_object('revision',n::text),$2::timestamptz+n*interval '1 second'
 FROM generate_series(0,1000) n`, tenant, from); err != nil {
				return err
			}
			_, err := sc.Q.Exec(ctx, `INSERT INTO change_events(tenant_id,title,occurred_at) VALUES
 ($1,'before month',$2::timestamptz-interval '1 microsecond'),($1,'next month',$3)`, tenant, from, to)
			return err
		})
	}
	for lane, tenant := range tenants {
		inTenant(t.Context(), t, pool, tenant, func(ctx context.Context, sc tenancy.Scope) error {
			values, err := (Incidents{}).ClientReportIncidentsInScope(ctx, sc, from, to, int64(2)<<30)
			if err != nil || len(values) != 1003 {
				t.Fatal("whole month was refused or shortened", len(values), err)
			}
			found := false
			for _, value := range values {
				if value.TenantID != tenant || value.Title == "ends exactly before month" || value.Title == "starts next month" {
					t.Fatal("monthly source crossed tenant or calendar boundary")
				}
				if value.ID == retainedIDs[tenant] {
					found = true
					if value.IdentityContextID != contextID || value.IdentityEntityID != entityID || !value.IdentityLookupAttempted {
						t.Fatal("monthly source lost canonical context needed for authorization")
					}
				}
			}
			if !found {
				t.Fatal("incident that crossed the month boundary was omitted")
			}
			if values, err := (Incidents{}).ClientReportIncidentsInScope(ctx, sc, from, to, 12<<10); !errors.Is(err, ErrClientReportBudget) || len(values) != 0 {
				t.Fatal("under-admitted month returned a plausible prefix", len(values), err)
			}
			foreign := tenancy.WithTenant(ctx, tenancy.ID(tenants[1-lane]))
			if values, err := (Incidents{}).ClientReportIncidentsInScope(foreign, sc, from, to, 32<<20); !errors.Is(err, entity.ErrScopeMismatch) || len(values) != 0 {
				t.Fatal("foreign context borrowed a monthly source scope")
			}
			changes, err := (ChangeEvents{}).ClientReportChangesInScope(ctx, sc, from, to, int64(2)<<30)
			if err != nil || len(changes) != 1001 {
				t.Fatal("monthly changes were refused or shortened", len(changes), err)
			}
			for index, value := range changes {
				if value.TenantID != tenant || value.Attributes["revision"] != fmt.Sprint(index) || value.OccurredAt.Before(from) || !value.OccurredAt.Before(to) {
					t.Fatal("monthly changes lost tenant, complete order, attributes or calendar bounds", index)
				}
				if index == 42 && len([]rune(value.Summary)) != 2000 {
					t.Fatal("monthly changes shortened source prose")
				}
			}
			if values, err := (ChangeEvents{}).ClientReportChangesInScope(ctx, sc, from, to, 12<<10); !errors.Is(err, ErrClientReportBudget) || len(values) != 0 {
				t.Fatal("under-admitted change month returned a plausible prefix", len(values), err)
			}
			if values, err := (ChangeEvents{}).ClientReportChangesInScope(foreign, sc, from, to, 32<<20); !errors.Is(err, entity.ErrScopeMismatch) || len(values) != 0 {
				t.Fatal("foreign context borrowed monthly changes")
			}
			return nil
		})
	}
}
