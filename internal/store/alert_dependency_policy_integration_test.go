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

	"github.com/ctlplne/probectl/internal/alert"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestAlertDependencyPolicyKeepsCurrentTenantParentsAndDetection(t *testing.T) {
	pool := setup(t.Context(), t)
	t.Cleanup(pool.Close)
	var tenants []string
	t.Cleanup(func() {
		if _, err := pool.Exec(context.Background(), `DELETE FROM tenants WHERE id=ANY($1::uuid[])`, tenants); err != nil {
			t.Error(err)
		}
	})
	type lane struct {
		tenant string
		rule   *alert.Rule
		policy alert.DependencyPolicy
	}
	var lanes []lane
	const maxBytes = 64 << 20
	publication := func(ctx context.Context, _ tenancy.Scope) error { return ctx.Err() }
	for i := range 2 {
		tenant, err := NewTenants(pool).Create(t.Context(), fmt.Sprintf("dependency-policy-%d-%d", i, time.Now().UnixNano()), "Dependency policy")
		if err != nil {
			t.Fatal(err)
		}
		tenants = append(tenants, tenant.ID)
		current := lane{tenant: tenant.ID}
		inTenant(t.Context(), t, pool, tenant.ID, func(ctx context.Context, sc tenancy.Scope) error {
			user, err := (Users{}).Create(ctx, sc, "dependency-owner@example.test", "Dependency owner")
			if err != nil {
				return err
			}
			contextID := uuid.NewString()
			if _, err := sc.Q.Exec(ctx, `INSERT INTO entity_contexts(tenant_id,id,site_id,vrf_id,site_label,vrf_label)
 VALUES($1,$2,$3,$4,'dependency site','dependency VRF')`, tenant.ID, contextID, uuid.NewString(), uuid.NewString()); err != nil {
				return err
			}
			current.policy = alert.DependencyPolicy{Version: 1, OwnerUserID: user.ID, ContextID: contextID, FreshnessSeconds: 300,
				ReadGrants: []alert.QueryReadGrant{{Permission: "topology.read", ScopeType: auth.ScopeTenant}}}
			current.rule, err = (AlertRules{}).Create(ctx, sc, alert.Rule{Name: "Existing reachability", Enabled: true, Metric: "probectl_probe_success", Type: alert.Threshold, Comparison: alert.EQ, Threshold: 0, Severity: alert.SeverityWarning})
			if err != nil {
				return err
			}
			if stored, err := (AlertRules{}).GetDependencyPolicy(ctx, sc, current.rule.ID, current.rule.UpdatedAt, maxBytes); err != nil || stored != nil {
				t.Fatal("ordinary detection acquired implicit notification policy", stored, err)
			}
			previous := current.rule
			current.rule, err = (AlertRules{}).SetDependencyPolicy(ctx, sc, previous.ID, previous.UpdatedAt, &current.policy, maxBytes, publication)
			if err == nil && (!current.rule.Enabled || current.rule.Metric != previous.Metric || current.rule.Comparison != previous.Comparison || current.rule.Threshold != previous.Threshold || !current.rule.HasDependencyPolicy) {
				return errors.New("notification policy changed ordinary detection")
			}
			return err
		})
		lanes = append(lanes, current)
	}
	for i, current := range lanes {
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(current.tenant))
		foreign := lanes[1-i]
		inTenant(ctx, t, pool, current.tenant, func(ctx context.Context, sc tenancy.Scope) error {
			stored, err := (AlertRules{}).GetDependencyPolicy(ctx, sc, current.rule.ID, current.rule.UpdatedAt, maxBytes)
			if err != nil || stored == nil || stored.OwnerUserID != current.policy.OwnerUserID || stored.ContextID != current.policy.ContextID {
				t.Fatal("current notification policy lost its tenant parents", stored, err)
			}
			if stored, err := (AlertRules{}).GetDependencyPolicy(ctx, sc, foreign.rule.ID, foreign.rule.UpdatedAt, maxBytes); !errors.Is(err, ErrAlertDependencyChanged) || stored != nil {
				t.Fatal("foreign notification policy crossed rule RLS", stored, err)
			}
			return nil
		})
		for _, mutate := range []func(*alert.DependencyPolicy){
			func(p *alert.DependencyPolicy) { p.OwnerUserID = foreign.policy.OwnerUserID },
			func(p *alert.DependencyPolicy) { p.ContextID = foreign.policy.ContextID },
		} {
			candidate := current.policy
			mutate(&candidate)
			err := tenancy.InTenant(ctx, pool, func(ctx context.Context, sc tenancy.Scope) error {
				_, err := (AlertRules{}).SetDependencyPolicy(ctx, sc, current.rule.ID, current.rule.UpdatedAt, &candidate, maxBytes, publication)
				return err
			})
			if !errors.Is(err, ErrAlertDependencyChanged) {
				t.Fatal("foreign owner or context became notification authority", err)
			}
		}
		inTenant(ctx, t, pool, current.tenant, func(ctx context.Context, sc tenancy.Scope) error {
			if changed, err := (AlertRules{}).SetDependencyPolicy(ctx, sc, current.rule.ID, current.rule.UpdatedAt, nil, maxBytes, nil); err == nil || changed != nil {
				t.Fatal("notification policy changed without publication authority", changed, err)
			}
			cleared, err := (AlertRules{}).SetDependencyPolicy(ctx, sc, current.rule.ID, current.rule.UpdatedAt, nil, maxBytes, publication)
			if err != nil || !cleared.Enabled || cleared.Metric != current.rule.Metric || cleared.HasDependencyPolicy {
				t.Fatal("clearing notification policy disabled or replaced detection", cleared, err)
			}
			if stale, err := (AlertRules{}).GetDependencyPolicy(ctx, sc, current.rule.ID, current.rule.UpdatedAt, maxBytes); !errors.Is(err, ErrAlertDependencyChanged) || stale != nil {
				t.Fatal("stale policy configuration remained current", stale, err)
			}
			if stored, err := (AlertRules{}).GetDependencyPolicy(ctx, sc, current.rule.ID, cleared.UpdatedAt, maxBytes); err != nil || stored != nil {
				t.Fatal("clear retained stored notification policy", stored, err)
			}
			return nil
		})
	}
	t.Log("real-integration: existing app-role PG/FORCE-RLS policy rows retain tenant owner/context, reject foreign/stale/publication-less edits and preserve detection through clear; no source, notification or served-surface claim")
}
