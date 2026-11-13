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
	"github.com/ctlplne/probectl/internal/incident"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport"
)

func TestCanonicalOverrideBatchKeepsExactShapeTenantReversalAndMutationLock(t *testing.T) {
	ctx := t.Context()
	pool := setup(ctx, t)
	t.Cleanup(pool.Close)
	testsupport.LockPostgresPublicCatalog(t, pool)
	var tenants []string
	for lane := range 2 {
		tenant, err := NewTenants(pool).Create(ctx, fmt.Sprintf("override-batch-%d-%d", lane, time.Now().UnixNano()), "override batch")
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
	area, first, second := uuid.NewString(), uuid.NewString(), uuid.NewString()
	for lane, tenant := range tenants {
		signals := make([]incident.Signal, 5)
		for i := range signals {
			signals[i] = incident.Signal{TenantID: tenant, Plane: "network", Kind: "alert.firing", Target: "192.0.2.7", Prefix: "203.0.113.0/24", IdentityLookupAttempted: true, IdentityContextID: area, IdentityEntityID: first}
		}
		signals[1].IdentityEntityID = second
		signals[2].Kind = "alert.resolved"
		signals[3].Target = "192.0.2.70"
		signals[4].Prefix = "203.0.113.0/25"
		inTenant(ctx, t, pool, tenant, func(ctx context.Context, sc tenancy.Scope) error {
			if _, err := sc.Q.Exec(ctx, `INSERT INTO entity_contexts(tenant_id,id,site_id,vrf_id,site_label,vrf_label) VALUES($1,$2,$2,$2,'neutral-site','neutral-vrf')`, tenant, area); err != nil {
				return err
			}
			if _, err := sc.Q.Exec(ctx, `INSERT INTO entities(tenant_id,context_id,id,kind,label) VALUES($1,$2,$3,'device','one'),($1,$2,$4,'device','two')`, tenant, area, first, second); err != nil {
				return err
			}
			parent, detached, signalID := uuid.NewString(), uuid.NewString(), uuid.NewString()
			if _, err := sc.Q.Exec(ctx, `INSERT INTO incidents(tenant_id,id,title) VALUES($1,$2,'parent'),($1,$3,'detached')`, tenant, parent, detached); err != nil {
				return err
			}
			if _, err := sc.Q.Exec(ctx, `INSERT INTO incident_signals(tenant_id,id,incident_id,plane,kind,severity,title,occurred_at) VALUES($1,$2,$3,'network','alert.firing','warning','fixture',clock_timestamp())`, tenant, signalID, parent); err != nil {
				return err
			}
			sig := signals[lane]
			_, err := sc.Q.Exec(ctx, `INSERT INTO incident_correlation_overrides(tenant_id,source_incident_id,detached_incident_id,source_signal_id,plane,kind,target,prefix,reason,created_by,entity_context_id,entity_id,identity_lookup_attempted)
 VALUES($1,$2,$3,$4,$5,$6,$7,$8,'operator fixture','fixture',$9,$10,true)`, tenant, parent, detached, signalID, sig.Plane, sig.Kind, sig.Target, sig.Prefix, area, sig.IdentityEntityID)
			return err
		})
		inTenant(ctx, t, pool, tenant, func(ctx context.Context, sc tenancy.Scope) error {
			out, err := (Incidents{}).ActiveCanonicalOverrideMatches(ctx, sc, signals, 1<<20)
			if err != nil || len(out) != len(signals) {
				t.Fatal("complete override match population unavailable", out, err)
			}
			for i, sig := range signals {
				original, err := (Incidents{}).ActiveCorrelationOverrides(ctx, sc, sig)
				if err != nil || out[i] != (len(original) != 0) || out[i] != (i == lane) {
					t.Fatal("batch borrowed a sibling or different signal shape", lane, i, out, err)
				}
			}
			other, err := pool.Begin(ctx)
			if err != nil {
				return err
			}
			defer func() { _ = other.Rollback(ctx) }()
			for _, candidate := range tenants {
				var acquired bool
				if err := other.QueryRow(ctx, `SELECT pg_try_advisory_xact_lock(hashtextextended('incident:'||$1::text,0))`, candidate).Scan(&acquired); err != nil {
					return err
				}
				if acquired != (candidate != tenant) {
					t.Fatal("override snapshot lost its mutation lock or locked a sibling", candidate == tenant, acquired)
				}
			}
			foreign := append([]incident.Signal(nil), signals...)
			foreign[0].TenantID = tenants[1-lane]
			if result, err := (Incidents{}).ActiveCanonicalOverrideMatches(ctx, sc, foreign, 1<<20); !errors.Is(err, entity.ErrScopeMismatch) || result != nil {
				t.Fatal("foreign member returned a usable override prefix", result, err)
			}
			if result, err := (Incidents{}).ActiveCanonicalOverrideMatches(ctx, sc, signals, 4096); !errors.Is(err, ErrAlertDependencyBudget) || result != nil {
				t.Fatal("memory refusal returned a usable override prefix", result, err)
			}
			_, err = sc.Q.Exec(ctx, `UPDATE incident_correlation_overrides SET active=false,reversed_by='fixture',reversal_reason='reversed',reversed_at=clock_timestamp() WHERE tenant_id=$1`, tenant)
			return err
		})
		inTenant(ctx, t, pool, tenant, func(ctx context.Context, sc tenancy.Scope) error {
			out, err := (Incidents{}).ActiveCanonicalOverrideMatches(ctx, sc, signals, 1<<20)
			if err != nil {
				return err
			}
			for _, matched := range out {
				if matched {
					t.Fatal("reversed exclusion remained active")
				}
			}
			return nil
		})
	}
	t.Log("real-integration: direct valid override fixtures compare original and batched app-role PG/RLS reads, exact shapes, reversal and tenant mutation locks")
}
