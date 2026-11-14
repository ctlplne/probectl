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
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// Real Postgres/FORCE-RLS configuration; source-read authority remains a
// separate served-reader proof. No seeded callback is called a live grant.
func TestAlertPathHealthSourceKeepsTenantParentsRevisionAndPublication(t *testing.T) {
	pool := setup(t.Context(), t)
	t.Cleanup(pool.Close)
	var tenants []string
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if _, err := pool.Exec(ctx, "DELETE FROM tenants WHERE id=ANY($1::uuid[])", tenants); err != nil {
			t.Error(err)
		}
	})
	const maxBytes = 64 << 20
	type lane struct {
		tenant string
		rule   *alert.Rule
		source alert.PathHealthSource
	}
	var lanes []*lane
	publication := func(ctx context.Context, sc tenancy.Scope) error {
		tenant, ok := tenancy.FromContext(ctx)
		if !ok || tenant != sc.Tenant {
			return tenancy.ErrNoTenant
		}
		return ctx.Err()
	}
	for i := range 2 {
		tenant, err := NewTenants(pool).Create(t.Context(), fmt.Sprintf("path-alert-%d-%d", i, time.Now().UnixNano()), "Path alert source")
		if err != nil {
			t.Fatal(err)
		}
		tenants = append(tenants, tenant.ID)
		current := &lane{tenant: tenant.ID}
		inTenant(t.Context(), t, pool, tenant.ID, func(ctx context.Context, sc tenancy.Scope) error {
			user, err := (Users{}).Create(ctx, sc, "path-owner@example.test", "Path owner")
			if err != nil {
				return err
			}
			test, err := (Tests{}).Create(ctx, sc, TestInput{Name: "Owned path", Type: "icmp", Target: "192.0.2.1", IntervalSeconds: 60, TimeoutSeconds: 3, Enabled: true})
			if err != nil {
				return err
			}
			contextID, deviceID, interfaceID := uuid.NewString(), uuid.NewString(), uuid.NewString()
			if _, err := sc.Q.Exec(ctx, "INSERT INTO entity_contexts(tenant_id,id,site_id,vrf_id,site_label,vrf_label) VALUES($1,$2,$3,$4,'owned','private')", current.tenant, contextID, uuid.NewString(), uuid.NewString()); err != nil {
				return err
			}
			if _, err := sc.Q.Exec(ctx, "INSERT INTO entities(tenant_id,context_id,id,kind,label) VALUES($1,$2,$3,'device','Owned device')", current.tenant, contextID, deviceID); err != nil {
				return err
			}
			if _, err := sc.Q.Exec(ctx, "INSERT INTO entities(tenant_id,context_id,id,kind,label,parent_entity_id) VALUES($1,$2,$3,'interface','Owned port',$4)", current.tenant, contextID, interfaceID, deviceID); err != nil {
				return err
			}
			input, err := alert.NormalizePathHealthSource(alert.PathHealthSourceInput{TestID: test.ID, InterfaceID: interfaceID, Metric: "probectl.device.if.in.fcs.errors"})
			if err != nil {
				return err
			}
			current.source = alert.PathHealthSource{PathHealthSourceInput: input, Version: 1, OwnerUserID: user.ID,
				ReadGrants: []alert.QueryReadGrant{{Permission: "metrics.read", ScopeType: auth.ScopeTenant}, {Permission: "test.read", ScopeType: auth.ScopeTenant}, {Permission: "entities.read", ScopeType: auth.ScopeTenant}}}
			current.rule, err = (AlertRules{}).Create(ctx, sc, alert.Rule{Name: "Owned FCS climb", Enabled: true, Type: alert.Threshold, Metric: alert.PathHealthMetric, Comparison: alert.GTE, Threshold: 1, Severity: alert.SeverityWarning})
			if err != nil {
				return err
			}
			current.rule, err = (AlertRules{}).SetPathHealthSource(ctx, sc, current.rule.ID, current.rule.UpdatedAt, &current.source, maxBytes, publication)
			return err
		})
		lanes = append(lanes, current)
	}
	for i, current := range lanes {
		other := lanes[1-i]
		inTenant(t.Context(), t, pool, current.tenant, func(ctx context.Context, sc tenancy.Scope) error {
			stored, err := (AlertRules{}).GetPathHealthSource(ctx, sc, current.rule.ID, current.rule.UpdatedAt, maxBytes)
			if err != nil || stored == nil || stored.OwnerUserID != current.source.OwnerUserID || stored.TestID != current.source.TestID {
				t.Fatal("owned path source lost its original parent/revision", err)
			}
			if foreign, err := (AlertRules{}).GetPathHealthSource(ctx, sc, other.rule.ID, other.rule.UpdatedAt, maxBytes); err == nil || foreign != nil {
				t.Fatal("foreign rule source crossed tenant storage scope")
			}
			for _, field := range []string{"owner", "test", "interface"} {
				forged := current.source
				if field == "owner" {
					forged.OwnerUserID = other.source.OwnerUserID
				} else if field == "test" {
					forged.TestID = other.source.TestID
				} else {
					forged.InterfaceID = other.source.InterfaceID
				}
				if _, err := (AlertRules{}).SetPathHealthSource(ctx, sc, current.rule.ID, current.rule.UpdatedAt, &forged, maxBytes, publication); err == nil {
					t.Fatal("foreign source parent was persisted", field)
				}
			}
			if _, err := (AlertRules{}).SetPathHealthSource(ctx, sc, current.rule.ID, current.rule.UpdatedAt, &current.source, maxBytes, nil); err == nil {
				t.Fatal("configuration write omitted its publication obligation")
			}
			withdrawn := errors.New("source grants withdrawn")
			if _, err := (AlertRules{}).SetPathHealthSource(ctx, sc, current.rule.ID, current.rule.UpdatedAt, &current.source, maxBytes, func(context.Context, tenancy.Scope) error { return withdrawn }); !errors.Is(err, withdrawn) {
				t.Fatal("failed publication check was ignored", err)
			}
			legacy := *current.rule
			legacy.Metric = "ordinary_metric"
			if _, err := (AlertRules{}).Update(ctx, sc, current.rule.ID, legacy); err == nil {
				t.Fatal("bound path source silently became a legacy metric rule")
			}
			mixed := &alert.TagFilter{Version: 1, TargetKind: "test", OwnerUserID: current.source.OwnerUserID, TagRevision: "1", AsOf: current.rule.UpdatedAt.Format(time.RFC3339Nano),
				Filter: &flow.QueryFilterGroup{Match: "all", Conditions: []flow.QueryPredicate{{Field: "tag.role", Op: flow.QueryEqual, Values: []string{"edge"}}}}, TagIDs: map[string]string{"tag.role": current.source.TestID}}
			if changed, err := (AlertRules{}).SetTagFilter(ctx, sc, current.rule.ID, current.rule.UpdatedAt, mixed); err == nil || changed != nil {
				t.Fatal("test-tag selection mixed with an owned path source", err)
			}
			previous := current.rule.UpdatedAt
			current.rule, err = (AlertRules{}).SetPathHealthSource(ctx, sc, current.rule.ID, previous, nil, maxBytes, publication)
			if err != nil || current.rule.Enabled {
				t.Fatal("explicit source clear did not disable evaluation", err)
			}
			if _, err := (AlertRules{}).SetPathHealthSource(ctx, sc, current.rule.ID, previous, &current.source, maxBytes, publication); err == nil {
				t.Fatal("stale source writer overwrote the new revision")
			}
			stored, err = (AlertRules{}).GetPathHealthSource(ctx, sc, current.rule.ID, current.rule.UpdatedAt, maxBytes)
			if err != nil || stored != nil {
				t.Fatal("cleared source retained old authority", err)
			}
			return nil
		})
	}
}
