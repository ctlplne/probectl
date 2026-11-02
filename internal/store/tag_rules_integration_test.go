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
	"github.com/jackc/pgx/v5"

	"github.com/ctlplne/probectl/internal/tags"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport"
)

func TestTagRuleWritesStayInTenantAndContext(t *testing.T) {
	ctx := context.Background()
	pool := setup(ctx, t)
	t.Cleanup(pool.Close)
	testsupport.LockPostgresPublicCatalog(t, pool)
	stamp := fmt.Sprintf("%d", time.Now().UnixNano())
	a, err := NewTenants(pool).Create(ctx, "tag-rule-a-"+stamp, "Tag rule A")
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewTenants(pool).Create(ctx, "tag-rule-b-"+stamp, "Tag rule B")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := pool.Exec(context.Background(), `DELETE FROM tenants WHERE id=ANY($1::uuid[])`,
			[]string{a.ID, b.ID}); err != nil {
			t.Errorf("remove tag rule tenants: %v", err)
		}
	})
	sharedContext := uuid.NewString()
	run := func(tenantID string, fn func(context.Context, tenancy.Scope) error) error {
		return tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenantID)), pool, fn)
	}
	var tagA, tagB tags.Definition
	for _, item := range []struct {
		tenantID string
		tag      *tags.Definition
	}{{a.ID, &tagA}, {b.ID, &tagB}} {
		if err := run(item.tenantID, func(ctx context.Context, sc tenancy.Scope) error {
			if _, err := sc.Q.Exec(ctx, `INSERT INTO entity_contexts
				(tenant_id,id,site_id,vrf_id,site_label,vrf_label)
				VALUES ($1,$2,$3,$4,'site','vrf')`, item.tenantID,
				sharedContext, uuid.NewString(), uuid.NewString()); err != nil {
				return err
			}
			var err error
			*item.tag, err = (TagDefinitions{}).Create(ctx, sc, "customer")
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	newRule := func(tenantID, tagID string) tags.Rule {
		return tags.Rule{Scope: tags.Scope{TenantID: tenantID, ContextID: sharedContext},
			TagID: tagID, TargetKind: "exporter", Match: "cidr", AddressSide: "exporter",
			CIDR: "10.42.0.0/16", Value: "blue", Priority: 7}
	}
	var ruleA tags.Rule
	if err := run(a.ID, func(ctx context.Context, sc tenancy.Scope) error {
		var err error
		ruleA, err = (TagRules{}).Create(ctx, sc, newRule(a.ID, tagA.ID))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := run(a.ID, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := (TagRules{}).Create(ctx, sc, newRule(a.ID, tagB.ID))
		return err
	}); !errors.Is(err, ErrTagReference) {
		t.Fatalf("foreign tenant tag accepted: %v", err)
	}
	if err := run(a.ID, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := (TagRules{}).Create(ctx, sc, tags.Rule{Scope: tags.Scope{
			TenantID: a.ID, ContextID: uuid.NewString()}, TagID: tagA.ID,
			TargetKind: "exporter", Match: "cidr", AddressSide: "exporter",
			CIDR: "10.42.0.0/16", Value: "blue"})
		return err
	}); !errors.Is(err, ErrTagReference) {
		t.Fatalf("foreign routing context accepted: %v", err)
	}
	if err := run(a.ID, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := (TagRules{}).Create(ctx, sc, tags.Rule{Scope: tags.Scope{
			TenantID: a.ID, ContextID: sharedContext}, TagID: tagA.ID,
			TargetKind: "exporter", Match: "name_pattern", NamePattern: "[",
			Value: "blue"})
		return err
	}); !errors.Is(err, tags.ErrInvalid) {
		t.Fatalf("invalid RE2 rule accepted: %v", err)
	}
	if err := run(b.ID, func(ctx context.Context, sc tenancy.Scope) error {
		items, _, err := (TagRules{}).List(ctx, sc, sharedContext, "", 100)
		if err != nil {
			return err
		}
		if len(items) != 0 {
			return fmt.Errorf("tenant B saw tenant A rules: %+v", items)
		}
		_, err = (TagRules{}).Update(ctx, sc, ruleA)
		if !errors.Is(err, tags.ErrScopeMismatch) {
			return fmt.Errorf("foreign update returned %v", err)
		}
		if err := (TagRules{}).Delete(ctx, sc, sharedContext, ruleA.ID); !errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("foreign delete returned %v", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	ruleA.Value = "green"
	if err := run(a.ID, func(ctx context.Context, sc tenancy.Scope) error {
		updated, err := (TagRules{}).Update(ctx, sc, ruleA)
		if err != nil || updated.Value != "green" {
			return fmt.Errorf("update rule: %+v %v", updated, err)
		}
		items, next, err := (TagRules{}).List(ctx, sc, sharedContext, "", 100)
		if err != nil || next != "" || len(items) != 1 || items[0].Value != "green" {
			return fmt.Errorf("list updated rule: %+v %q %v", items, next, err)
		}
		return (TagRules{}).Delete(ctx, sc, sharedContext, ruleA.ID)
	}); err != nil {
		t.Fatal(err)
	}
}
