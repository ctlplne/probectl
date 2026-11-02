// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration || isolation

package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/ctlplne/probectl/internal/tags"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport"
)

func TestTagValueCharacterReachAndBytePagedMetadataStayTenantScoped(t *testing.T) {
	ctx := context.Background()
	pool := setup(ctx, t)
	t.Cleanup(pool.Close)
	testsupport.LockPostgresPublicCatalog(t, pool)
	stamp := fmt.Sprintf("%d", time.Now().UnixNano())
	a, err := NewTenants(pool).Create(ctx, "tag-values-a-"+stamp, "Tag values A")
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewTenants(pool).Create(ctx, "tag-values-b-"+stamp, "Tag values B")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := pool.Exec(context.Background(), `DELETE FROM tenants WHERE id=ANY($1::uuid[])`, []string{a.ID, b.ID}); err != nil {
			t.Error(err)
		}
	})
	contextID, tagID := uuid.NewString(), uuid.NewString()
	deviceIDs := make([]string, 25)
	for i := range deviceIDs {
		deviceIDs[i] = uuid.NewString()
	}
	value := strings.Repeat("🌐", 24000)
	run := func(tenant string, fn func(context.Context, tenancy.Scope) error) error {
		return tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenant)), pool, fn)
	}
	for _, tenant := range []string{a.ID, b.ID} {
		if err := run(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			for _, sql := range []string{
				`INSERT INTO entity_contexts(tenant_id,id,site_id,vrf_id,site_label,vrf_label) VALUES ($1,$2,$2,$2,'site','vrf')`,
			} {
				if _, err := sc.Q.Exec(ctx, sql, tenant, contextID); err != nil {
					return err
				}
			}
			if _, err := sc.Q.Exec(ctx, `INSERT INTO tenant_tag_definitions(tenant_id,id,key) VALUES ($1,$2,'customer')`, tenant, tagID); err != nil {
				return err
			}
			if _, err := sc.Q.Exec(ctx, `INSERT INTO entities(tenant_id,context_id,id,kind,label) SELECT $1,$2,unnest($3::uuid[]),'device','router'`, tenant, contextID, deviceIDs); err != nil {
				return err
			}
			for i, id := range deviceIDs {
				ownValue := value
				if tenant == b.ID {
					if i > 0 {
						break
					}
					ownValue = "tenant-b"
				}
				if _, err := (TagAssignments{}).CreateManual(ctx, sc, ManualTagAssignmentInput{Scope: tags.Scope{TenantID: tenant, ContextID: contextID}, TagID: tagID, TargetKind: "device", TargetID: id, Value: ownValue}); err != nil {
					return err
				}
				if _, err := (TagRules{}).Create(ctx, sc, tags.Rule{Scope: tags.Scope{TenantID: tenant, ContextID: contextID}, TagID: tagID, TargetKind: "device", Match: "name_pattern", NamePattern: "^router$", Value: ownValue}); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	for _, tenant := range []string{a.ID, b.ID} {
		want := 25
		if tenant == b.ID {
			want = 1
		}
		seenAssignments, seenRules := map[string]bool{}, map[string]bool{}
		assignmentPages, rulePages := 0, 0
		if err := run(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			cursor := ""
			for {
				items, next, err := (TagAssignments{}).List(ctx, sc, contextID, cursor, 100)
				if err != nil {
					return err
				}
				encoded, err := json.Marshal(items)
				if err != nil {
					return err
				}
				if len(encoded) > maxTagPageBytes+2 {
					return fmt.Errorf("assignment page exceeded encoded budget: %d", len(encoded))
				}
				assignmentPages++
				for _, item := range items {
					if seenAssignments[item.ID] || item.TenantID != tenant || item.ContextID != contextID {
						return fmt.Errorf("assignment cursor crossed scope or repeated a row")
					}
					if (tenant == a.ID && item.Value != value) || (tenant == b.ID && item.Value != "tenant-b") {
						return fmt.Errorf("assignment returned another tenant's value")
					}
					seenAssignments[item.ID] = true
				}
				if next == "" {
					break
				}
				if next == cursor || len(items) == 0 {
					return fmt.Errorf("assignment cursor did not advance")
				}
				cursor = next
			}
			cursor = ""
			for {
				items, next, err := (TagRules{}).List(ctx, sc, contextID, cursor, 100)
				if err != nil {
					return err
				}
				encoded, err := json.Marshal(items)
				if err != nil {
					return err
				}
				if len(encoded) > maxTagPageBytes+2 {
					return fmt.Errorf("rule page exceeded encoded budget: %d", len(encoded))
				}
				rulePages++
				for _, item := range items {
					if seenRules[item.ID] || item.TenantID != tenant || item.ContextID != contextID {
						return fmt.Errorf("rule cursor crossed scope or repeated a row")
					}
					if (tenant == a.ID && item.Value != value) || (tenant == b.ID && item.Value != "tenant-b") {
						return fmt.Errorf("rule returned another tenant's value")
					}
					seenRules[item.ID] = true
				}
				if next == "" {
					break
				}
				if next == cursor || len(items) == 0 {
					return fmt.Errorf("rule cursor did not advance")
				}
				cursor = next
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if len(seenAssignments) != want || len(seenRules) != want || (tenant == a.ID && (assignmentPages < 2 || rulePages < 2)) {
			t.Fatalf("tenant %s paging dropped metadata: assignments=%d rules=%d pages=%d/%d", tenant, len(seenAssignments), len(seenRules), assignmentPages, rulePages)
		}
	}
	for _, table := range []string{"tenant_tag_assignments", "tenant_tag_rules"} {
		err := run(a.ID, func(ctx context.Context, sc tenancy.Scope) error {
			_, err := sc.Q.Exec(ctx, `UPDATE `+table+` SET value=$2 WHERE tenant_id=$1`, a.ID, strings.Repeat("🌐", 24001))
			return err
		})
		var pgError *pgconn.PgError
		if !errors.As(err, &pgError) || pgError.Code != "23514" {
			t.Fatalf("%s storage value CHECK did not refuse an oversized direct write: %v", table, err)
		}
	}
}
