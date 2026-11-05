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
	"net/netip"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/tags"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport"
)

func TestTagCardinalityUsesCompleteResourceAdmissionAndTenantIsolation(t *testing.T) {
	ctx := t.Context()
	pool := setup(ctx, t)
	t.Cleanup(pool.Close)
	testsupport.LockPostgresPublicCatalog(t, pool)
	stamp := fmt.Sprint(time.Now().UnixNano())
	var tenants []string
	for _, lane := range []string{"a", "b"} {
		tenant, err := NewTenants(pool).Create(ctx, "tag-capacity-"+lane+"-"+stamp, "Tag capacity")
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
	contextID := uuid.NewString()
	const tagID = "10000000-0000-4000-8000-000000000001"
	const lastEntity = "20000000-0000-4000-8000-000000025001"
	lastRules := make(map[string]tags.Rule)
	for lane, tenant := range tenants {
		owned := tenancy.WithTenant(ctx, tenancy.ID(tenant))
		var lastRule tags.Rule
		err := tenancy.InTenant(owned, pool, func(ctx context.Context, sc tenancy.Scope) error {
			if _, err := sc.Q.Exec(ctx, `INSERT INTO entity_contexts(tenant_id,id,site_id,vrf_id,site_label,vrf_label) VALUES($1,$2,$2,$2,'capacity-site','capacity-vrf')`, tenant, contextID); err != nil {
				return err
			}
			if _, err := sc.Q.Exec(ctx, `INSERT INTO tenant_tag_definitions(tenant_id,id,key)
 SELECT $1,('10000000-0000-4000-8000-'||lpad(i::text,12,'0'))::uuid,'custom_'||lpad(i::text,3,'0') FROM generate_series(1,128) AS g(i)`, tenant); err != nil {
				return err
			}
			if _, err := (TagDefinitions{}).Create(ctx, sc, "custom_129"); err != nil {
				return fmt.Errorf("above-former definition write refused: %w", err)
			}
			if _, err := sc.Q.Exec(ctx, `INSERT INTO entities(tenant_id,context_id,id,kind,label)
 SELECT $1,$2,('20000000-0000-4000-8000-'||lpad(i::text,12,'0'))::uuid,'device','capacity-device' FROM generate_series(1,25001) AS g(i)`, tenant, contextID); err != nil {
				return err
			}
			if _, err := sc.Q.Exec(ctx, `INSERT INTO tenant_tag_assignments(tenant_id,context_id,id,tag_id,target_kind,entity_id,entity_kind,value,source)
 SELECT $1,$2,('30000000-0000-4000-8000-'||lpad(i::text,12,'0'))::uuid,$3,'device',('20000000-0000-4000-8000-'||lpad(i::text,12,'0'))::uuid,'device',$4,'manual' FROM generate_series(1,25000) AS g(i)`, tenant, contextID, tagID, fmt.Sprintf("lane-%d-assignment", lane)); err != nil {
				return err
			}
			if _, err := (TagAssignments{}).CreateManual(ctx, sc, ManualTagAssignmentInput{Scope: tags.Scope{TenantID: tenant, ContextID: contextID}, TagID: tagID, TargetKind: "device", TargetID: lastEntity, Value: fmt.Sprintf("lane-%d-last-assignment", lane)}); err != nil {
				return fmt.Errorf("above-former assignment write refused: %w", err)
			}
			if _, err := sc.Q.Exec(ctx, `INSERT INTO tenant_tag_rules(tenant_id,context_id,id,tag_id,target_kind,match_kind,address_side,cidr,value)
 SELECT $1,$2,('40000000-0000-4000-8000-'||lpad(i::text,12,'0'))::uuid,$3,'device','cidr','device','10.0.0.0/8',$4 FROM generate_series(1,25000) AS g(i)`, tenant, contextID, tagID, fmt.Sprintf("lane-%d-rule", lane)); err != nil {
				return err
			}
			var err error
			lastRule, err = (TagRules{}).Create(ctx, sc, tags.Rule{Scope: tags.Scope{TenantID: tenant, ContextID: contextID}, TagID: tagID, TargetKind: "device", Match: "cidr", AddressSide: "device", CIDR: "10.99.255.1/32", Value: fmt.Sprintf("lane-%d-last-rule", lane)})
			if err != nil {
				return fmt.Errorf("above-former rule write refused: %w", err)
			}
			definitions, err := (TagDefinitions{}).ListBounded(ctx, sc, 4<<20)
			if err != nil || len(definitions) != 129 {
				return fmt.Errorf("complete larger vocabulary missing: count=%d error=%v", len(definitions), err)
			}
			if partial, err := (TagDefinitions{}).ListBounded(ctx, sc, 8192); !errors.Is(err, ErrTagSnapshotBudget) || partial != nil {
				return fmt.Errorf("small vocabulary budget returned partial or success: %v", err)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		lastRules[tenant] = lastRule
	}
	// Both complete datasets exist before any foreign-read or snapshot check.
	for lane, tenant := range tenants {
		owned := tenancy.WithTenant(ctx, tenancy.ID(tenant))
		if err := tenancy.InTenant(owned, pool, func(ctx context.Context, sc tenancy.Scope) error {
			var foreign int
			if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM tenant_tag_assignments WHERE tenant_id=$1`, tenants[1-lane]).Scan(&foreign); err != nil {
				return err
			}
			if foreign != 0 {
				return errors.New("larger tag state escaped tenant FORCE-RLS")
			}
			remaining := int64(256 << 20)
			charge := func(parts ...string) error {
				cost := int64(2048)
				for _, part := range parts {
					cost += int64(len(part))
				}
				if cost > remaining {
					return ErrTagSnapshotBudget
				}
				remaining -= cost
				return nil
			}
			scope := tags.Scope{TenantID: tenant, ContextID: contextID}
			rules, err := loadTagRules(ctx, sc, scope, charge)
			if err != nil || len(rules) != 25001 {
				return fmt.Errorf("complete above-former rules truncated: count=%d error=%v", len(rules), err)
			}
			assignments, err := loadTagAssignments(ctx, sc, scope, charge)
			if err != nil || len(assignments) != 25001 {
				return fmt.Errorf("complete above-former assignments truncated: count=%d error=%v", len(assignments), err)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		scope := tags.Scope{TenantID: tenant, ContextID: contextID}
		if partial, err := loadContextTagSnapshotForTest(owned, pool, scope, 32<<10); partial != nil || !errors.Is(err, ErrTagSnapshotBudget) {
			t.Fatal("small snapshot budget returned partial or success", err)
		}
		snapshot, err := loadContextTagSnapshotForTest(owned, pool, scope, 256<<20)
		if err != nil {
			t.Fatal("above-former snapshot read refused", err)
		}
		for _, check := range []struct {
			subject         tags.Subject
			value, sourceID string
		}{
			{tags.Subject{Scope: scope, Kind: "device", ID: lastEntity}, fmt.Sprintf("lane-%d-last-assignment", lane), ""},
			{tags.Subject{Scope: scope, Kind: "device", ID: uuid.NewString(), AddressSide: "device", Address: netip.MustParseAddr("10.99.255.1")}, fmt.Sprintf("lane-%d-last-rule", lane), lastRules[tenant].ID},
		} {
			got, err := snapshot.ResolveContext(ctx, check.subject)
			if err != nil || len(got) != 1 || got[0].Value != check.value || (check.sourceID != "" && got[0].SourceID != check.sourceID) {
				t.Fatal("above-former metadata was truncated or crossed tenants", got, err)
			}
		}
	}
}
