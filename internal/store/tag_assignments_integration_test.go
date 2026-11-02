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

func TestManualTagAssignmentWritesStayInTenantAndContext(t *testing.T) {
	ctx := context.Background()
	pool := setup(ctx, t)
	t.Cleanup(pool.Close)
	testsupport.LockPostgresPublicCatalog(t, pool)
	stamp := fmt.Sprintf("%d", time.Now().UnixNano())
	a, err := NewTenants(pool).Create(ctx, "tag-assignment-a-"+stamp, "Tag assignment A")
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewTenants(pool).Create(ctx, "tag-assignment-b-"+stamp, "Tag assignment B")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := pool.Exec(context.Background(), `DELETE FROM tenants WHERE id=ANY($1::uuid[])`,
			[]string{a.ID, b.ID}); err != nil {
			t.Errorf("remove tag assignment tenants: %v", err)
		}
	})
	sharedContext, sharedEntity := uuid.NewString(), uuid.NewString()
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
			if _, err := sc.Q.Exec(ctx, `INSERT INTO entities
				(tenant_id,context_id,id,kind,label)
				VALUES ($1,$2,$3,'device','router')`, item.tenantID,
				sharedContext, sharedEntity); err != nil {
				return err
			}
			var err error
			*item.tag, err = (TagDefinitions{}).Create(ctx, sc, "customer")
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	input := func(tenantID, tagID string) ManualTagAssignmentInput {
		return ManualTagAssignmentInput{Scope: tags.Scope{
			TenantID: tenantID, ContextID: sharedContext}, TagID: tagID,
			TargetKind: "device", TargetID: sharedEntity, Value: "blue"}
	}
	var record TagAssignmentRecord
	if err := run(a.ID, func(ctx context.Context, sc tenancy.Scope) error {
		var err error
		record, err = (TagAssignments{}).CreateManual(ctx, sc, input(a.ID, tagA.ID))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if record.ID == "" || record.TenantID != a.ID || record.TargetID != sharedEntity {
		t.Fatalf("manual assignment lost tenant/subject: %+v", record)
	}
	if err := run(a.ID, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := (TagAssignments{}).CreateManual(ctx, sc, input(a.ID, tagB.ID))
		return err
	}); !errors.Is(err, ErrTagReference) {
		t.Fatalf("foreign tenant tag accepted: %v", err)
	}
	wrongKind := input(a.ID, tagA.ID)
	wrongKind.TargetKind = "interface"
	if err := run(a.ID, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := (TagAssignments{}).CreateManual(ctx, sc, wrongKind)
		return err
	}); !errors.Is(err, ErrTagReference) {
		t.Fatalf("wrong canonical kind accepted: %v", err)
	}
	for _, tenantID := range []string{a.ID, b.ID} {
		if err := run(tenantID, func(ctx context.Context, sc tenancy.Scope) error {
			items, next, err := (TagAssignments{}).List(ctx, sc, sharedContext, "", 100)
			if err != nil || next != "" {
				return fmt.Errorf("list assignments: %v %s", err, next)
			}
			if tenantID == a.ID && (len(items) != 1 || items[0].ID != record.ID) {
				return fmt.Errorf("tenant A assignment missing: %+v", items)
			}
			if tenantID == b.ID && len(items) != 0 {
				return fmt.Errorf("tenant B saw tenant A assignments: %+v", items)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := run(b.ID, func(ctx context.Context, sc tenancy.Scope) error {
		if err := (TagAssignments{}).DeleteManual(ctx, sc, sharedContext, record.ID); !errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("foreign delete returned %v", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	changed := input(a.ID, tagA.ID)
	changed.Value = "green"
	if err := run(a.ID, func(ctx context.Context, sc tenancy.Scope) error {
		updated, err := (TagAssignments{}).UpdateManual(ctx, sc, record.ID, changed)
		if err != nil || updated.Value != "green" {
			return fmt.Errorf("update assignment: %+v %v", updated, err)
		}
		return (TagAssignments{}).DeleteManual(ctx, sc, sharedContext, record.ID)
	}); err != nil {
		t.Fatal(err)
	}
}
