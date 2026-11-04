// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package control

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tags"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// The parent owns actual TLS, tokens/current roles, consent and call audits.
// This is native/Postgres component proof, not a release/sender/browser proof.
func proveTargetlessTestNativeContext(t *testing.T, pool *pgxpool.Pool, tenants []string, contextID string,
	native func(string, string, any, bool) json.RawMessage, grant func(string, bool) error) {
	t.Helper()
	ctx := t.Context()
	ids, definitions, granted := map[string]string{}, map[string]string{}, map[string]bool{}
	defer func() {
		for _, tenant := range tenants {
			if granted[tenant] {
				if err := grant(tenant, false); err != nil {
					t.Error("temporary native context grant cleanup failed")
				}
			}
			if err := tenancy.InTenant(tenancy.WithTenant(context.Background(), tenancy.ID(tenant)), pool, func(ctx context.Context, sc tenancy.Scope) error {
				if definitions[tenant] != "" {
					if _, err := sc.Q.Exec(ctx, `DELETE FROM tenant_tag_definitions WHERE tenant_id=$1 AND id=$2`, tenant, definitions[tenant]); err != nil {
						return err
					}
				}
				if ids[tenant] != "" {
					_, err := sc.Q.Exec(ctx, `DELETE FROM tests WHERE tenant_id=$1 AND id=$2`, tenant, ids[tenant])
					return err
				}
				return nil
			}); err != nil {
				t.Error("owned targetless native fixture cleanup failed")
			}
		}
	}()
	for _, tenant := range tenants {
		ids[tenant] = uuid(t)
		if err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenant)), pool, func(ctx context.Context, sc tenancy.Scope) error {
			if _, err := sc.Q.Exec(ctx, `INSERT INTO tests(tenant_id,id,name,type,target) VALUES ($1,$2,'same-native-noop','noop','')`, tenant, ids[tenant]); err != nil {
				return err
			}
			definition, err := (store.TagDefinitions{}).Create(ctx, sc, "noop_customer")
			if err != nil {
				return err
			}
			definitions[tenant] = definition.ID
			_, err = (store.TagRules{}).Create(ctx, sc, tags.Rule{Scope: tags.Scope{TenantID: tenant, ContextID: contextID},
				TagID: definition.ID, TargetKind: "test", Match: "name_pattern", NamePattern: "^same-native-noop$", Value: "own-" + tenant})
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	for lane, tenant := range tenants {
		foreign := tenants[1-lane]
		input := map[string]string{"test_id": ids[tenant], "context_id": contextID}
		native(tenant, "entity_path_context_assign", input, false)
		if err := grant(tenant, true); err != nil {
			t.Fatal("explicit native context write grant failed", err)
		}
		granted[tenant] = true
		var binding struct {
			TestID    string `json:"test_id"`
			ContextID string `json:"context_id"`
		}
		if json.Unmarshal(native(tenant, "entity_path_context_assign", input, true), &binding) != nil || binding.TestID != ids[tenant] || binding.ContextID != contextID {
			t.Fatal("native targetless binding lost its exact owned test/context")
		}
		native(tenant, "entity_path_context_assign", map[string]string{"test_id": ids[foreign], "context_id": contextID}, false)
		var projection tags.TestContextResolution
		if json.Unmarshal(native(tenant, "test_tag_context", tags.TestContextInput{TestIDs: []string{ids[tenant], ids[foreign]}}, true), &projection) != nil || len(projection.Items) != 1 || projection.Items[0].TargetID != ids[tenant] || projection.Items[0].ContextID != contextID || len(projection.Items[0].Items) != 1 {
			t.Fatal("native targetless metadata disclosed a foreign test or lost its owned result")
		}
		value := projection.Items[0].Items[0]
		if value.TagID != definitions[tenant] || value.Key != "noop_customer" || value.Value != "own-"+tenant || value.Source != "rule" || projection.TagRevision == "" || projection.AsOf == "" {
			t.Fatal("native targetless metadata lost exact current rule provenance")
		}
		if err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenant)), pool, func(ctx context.Context, sc tenancy.Scope) error {
			var paths, audits int
			if err := sc.Q.QueryRow(ctx, `SELECT
				(SELECT count(*) FROM entity_path_test_contexts WHERE tenant_id=$1 AND test_id=$2),
				(SELECT count(*) FROM audit_events WHERE tenant_id=$1 AND action='entity.path_context.assigned' AND target=$3)`, tenant, ids[tenant], ids[tenant]).Scan(&paths, &audits); err != nil {
				return err
			}
			if paths != 0 || audits != 1 {
				t.Fatal("native metadata-only binding acquired path authority or lost its atomic audit")
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if err := grant(tenant, false); err != nil {
			t.Fatal("native context write grant withdrawal failed", err)
		}
		granted[tenant] = false
		native(tenant, "entity_path_context_assign", input, false)
	}
}
