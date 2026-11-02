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

	"github.com/jackc/pgx/v5"

	"github.com/ctlplne/probectl/internal/tags"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport"
)

func TestTagDefinitionWritesStayInTenantAndAdvanceRevision(t *testing.T) {
	ctx := context.Background()
	pool := setup(ctx, t)
	t.Cleanup(pool.Close)
	testsupport.LockPostgresPublicCatalog(t, pool)
	stamp := fmt.Sprintf("%d", time.Now().UnixNano())
	a, err := NewTenants(pool).Create(ctx, "tag-def-a-"+stamp, "Tag definition A")
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewTenants(pool).Create(ctx, "tag-def-b-"+stamp, "Tag definition B")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := pool.Exec(context.Background(), `DELETE FROM tenants WHERE id=ANY($1::uuid[])`,
			[]string{a.ID, b.ID}); err != nil {
			t.Errorf("remove tag definition tenants: %v", err)
		}
	})
	run := func(tenantID string, fn func(context.Context, tenancy.Scope) error) error {
		return tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenantID)), pool, fn)
	}
	var definitionA, definitionB tags.Definition
	for _, row := range []struct {
		tenantID string
		out      *tags.Definition
	}{{a.ID, &definitionA}, {b.ID, &definitionB}} {
		if err := run(row.tenantID, func(ctx context.Context, sc tenancy.Scope) error {
			var err error
			*row.out, err = (TagDefinitions{}).Create(ctx, sc, "customer")
			return err
		}); err != nil {
			t.Fatalf("create tag in tenant %s: %v", row.tenantID, err)
		}
	}
	if definitionA.ID == definitionB.ID || definitionA.TenantID == definitionB.TenantID {
		t.Fatalf("tenant definitions collapsed: %+v, %+v", definitionA, definitionB)
	}
	for _, row := range []struct {
		tenantID, wantID string
	}{{a.ID, definitionA.ID}, {b.ID, definitionB.ID}} {
		if err := run(row.tenantID, func(ctx context.Context, sc tenancy.Scope) error {
			definitions, err := (TagDefinitions{}).List(ctx, sc)
			if err != nil {
				return err
			}
			if len(definitions) != 1 || definitions[0].ID != row.wantID {
				return fmt.Errorf("tenant %s saw foreign tag definitions: %+v", row.tenantID, definitions)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := run(a.ID, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := (TagDefinitions{}).Rename(ctx, sc, definitionB.ID, "foreign")
		if !errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("foreign rename returned %v, want no rows", err)
		}
		if err := (TagDefinitions{}).Delete(ctx, sc, definitionB.ID); !errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("foreign delete returned %v, want no rows", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := run(a.ID, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := (TagDefinitions{}).Create(ctx, sc, "customer")
		return err
	}); !errors.Is(err, tags.ErrConflict) {
		t.Fatalf("duplicate key returned %v, want conflict", err)
	}
	var revisionBefore int64
	if err := pool.QueryRow(ctx, `SELECT revision FROM tenant_tag_revisions WHERE tenant_id=$1`,
		a.ID).Scan(&revisionBefore); err != nil {
		t.Fatal(err)
	}
	if err := run(a.ID, func(ctx context.Context, sc tenancy.Scope) error {
		if _, err := (TagDefinitions{}).Rename(ctx, sc, definitionA.ID, "tenant_id"); !errors.Is(err, tags.ErrInvalid) {
			return fmt.Errorf("reserved key returned %v, want invalid", err)
		}
		renamed, err := (TagDefinitions{}).Rename(ctx, sc, definitionA.ID, "customer_new")
		if err != nil || renamed.Key != "customer_new" {
			return fmt.Errorf("rename result %+v: %v", renamed, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	var revisionAfter int64
	if err := pool.QueryRow(ctx, `SELECT revision FROM tenant_tag_revisions WHERE tenant_id=$1`,
		a.ID).Scan(&revisionAfter); err != nil || revisionAfter <= revisionBefore {
		t.Fatalf("rename did not advance revision: %d -> %d, %v", revisionBefore, revisionAfter, err)
	}
	if err := run(b.ID, func(ctx context.Context, sc tenancy.Scope) error {
		definitions, err := (TagDefinitions{}).List(ctx, sc)
		if err != nil {
			return err
		}
		if len(definitions) != 1 || definitions[0].ID != definitionB.ID || definitions[0].Key != "customer" {
			return fmt.Errorf("tenant A rename changed tenant B: %+v", definitions)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
