// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package tenantlife

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/store/flowsnapshot"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport"
)

// Real Postgres/FORCE-RLS and lifecycle export/erasure. Retained configuration
// is seeded directly, not claimed as sender or public API proof. Both tenants
// have the same row/context IDs and subject text, with a whole >4MiB policy.
func TestInterfaceRoleSubjectKeepsWholeExportErasureAndTenantIsolation(t *testing.T) {
	pool := itPool(t)
	t.Cleanup(pool.Close)
	testsupport.LockPostgresPublicCatalog(t, pool)
	ctx := t.Context()
	stamp := fmt.Sprint(time.Now().UnixNano())
	tenants := []string{mkTenant(t, pool, "role-subject-a-"+stamp), mkTenant(t, pool, "role-subject-b-"+stamp)}
	t.Cleanup(func() {
		if _, err := pool.Exec(context.Background(), `DELETE FROM tenants WHERE id=ANY($1::uuid[])`, tenants); err != nil {
			t.Error(err)
		}
	})
	const person = "role-policy-owner@example.test"
	contextID, unrelatedContext, interfaceID, policyID, otherPolicyID, overrideID := uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString()
	definition := entity.InterfaceRolePolicyDefinition{ProviderASNs: []uint32{4294967295}, CustomerASNs: []uint32{64602}, DescriptionRules: []entity.InterfaceRoleDescriptionRule{}}
	for i := range 4096 {
		definition.DescriptionRules = append(definition.DescriptionRules, entity.InterfaceRoleDescriptionRule{ID: uuid.NewString(), Pattern: "^" + strings.Repeat("unrelated-uplink-", 80) + fmt.Sprint(i) + "$", Role: entity.InterfaceRoleBackbone})
	}
	definition.DescriptionRules = append(definition.DescriptionRules, entity.InterfaceRoleDescriptionRule{ID: uuid.NewString(), Pattern: "^device-admin-" + person + "-東京$", Role: entity.InterfaceRolePrivate})
	raw, err := json.Marshal(definition)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) <= 4<<20 {
		t.Fatal("whole policy subject fixture lost complete metadata reach", len(raw))
	}
	neutral, err := json.Marshal(entity.InterfaceRolePolicyDefinition{ProviderASNs: []uint32{}, CustomerASNs: []uint32{}, DescriptionRules: []entity.InterfaceRoleDescriptionRule{}})
	if err != nil {
		t.Fatal(err)
	}
	generations := map[string]int64{}
	for _, tenant := range tenants {
		err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenant)), pool, func(ctx context.Context, sc tenancy.Scope) error {
			for _, id := range []string{contextID, unrelatedContext} {
				if _, err := sc.Q.Exec(ctx, `INSERT INTO entity_contexts(tenant_id,id,site_id,vrf_id,site_label,vrf_label) VALUES($1,$2,$2,$2,'neutral-site','neutral-vrf')`, tenant, id); err != nil {
					return err
				}
			}
			if _, err := sc.Q.Exec(ctx, `INSERT INTO entities(tenant_id,context_id,id,kind,label) VALUES($1,$2,$3,'interface','neutral-interface')`, tenant, contextID, interfaceID); err != nil {
				return err
			}
			for _, item := range []struct {
				context, id string
				body        []byte
			}{{contextID, policyID, raw}, {unrelatedContext, otherPolicyID, neutral}} {
				if _, err := sc.Q.Exec(ctx, `INSERT INTO interface_role_policies(tenant_id,context_id,id,definition) VALUES($1,$2,$3,$4::jsonb)`, tenant, item.context, item.id, string(item.body)); err != nil {
					return err
				}
			}
			if _, err := sc.Q.Exec(ctx, `INSERT INTO interface_role_overrides(tenant_id,context_id,interface_id,id,role) VALUES($1,$2,$3,$4,'backbone')`, tenant, contextID, interfaceID, overrideID); err != nil {
				return err
			}
			var err error
			generations[tenant], err = flowsnapshot.SourceGenerationInScope(ctx, sc)
			return err
		})
		if err != nil {
			t.Fatal("retained role lifecycle fixture", err)
		}
	}
	sink := func(ctx context.Context, actor, action, target string, data map[string]any) error {
		_, err := audit.ProviderAppend(ctx, pool, actor, action, target, data)
		return err
	}
	engine := New(pool, nil, nil, nil, sink, "fixture backups expire", nil)
	var bundle bytes.Buffer
	if _, err := engine.ExportSubject(ctx, tenants[0], person, &bundle, false); err != nil {
		t.Fatal("role policy subject export failed", err)
	}
	files := readTarGz(t, bundle.Bytes())
	lines := strings.Split(strings.TrimSpace(files["postgres/interface_role_policies.jsonl"]), "\n")
	if len(lines) != 1 || lines[0] == "" {
		t.Fatal("role policy subject export omitted owned text or selected unrelated rows", len(lines))
	}
	var exported struct {
		Tenant     string                               `json:"tenant_id"`
		Context    string                               `json:"context_id"`
		ID         string                               `json:"id"`
		Definition entity.InterfaceRolePolicyDefinition `json:"definition"`
	}
	if err := json.Unmarshal([]byte(lines[0]), &exported); err != nil {
		t.Fatal(err)
	}
	if exported.Tenant != tenants[0] || exported.Context != contextID || exported.ID != policyID || !reflect.DeepEqual(exported.Definition, definition) {
		t.Fatal("role policy portability changed complete values, order, Unicode or tenant identity")
	}
	if strings.TrimSpace(files["postgres/interface_role_overrides.jsonl"]) != "" {
		t.Fatal("fixed role override acquired a fabricated personal subject")
	}
	result, err := engine.EraseSubject(ctx, tenants[0], person, "privacy-admin", "role metadata lifecycle")
	if err != nil || !result.Complete {
		t.Fatal("role policy subject erasure was incomplete", err, result)
	}
	plane := subjectPlanesByName(result.Planes)["postgres:interface_role_policies"]
	if plane.Status != SubjectStatusDeleted || plane.Deleted != 1 || plane.Remaining != 0 {
		t.Fatal("role policy subject erasure retained owned text or deleted unrelated rows", plane)
	}
	for lane, tenant := range tenants {
		err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenant)), pool, func(ctx context.Context, sc tenancy.Scope) error {
			var foreign, policies, overrides int
			if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM interface_role_policies WHERE tenant_id=$1`, tenants[1-lane]).Scan(&foreign); err != nil {
				return err
			}
			if foreign != 0 {
				t.Fatal("role policy foreign FORCE-RLS read succeeded")
			}
			if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM interface_role_policies`).Scan(&policies); err != nil {
				return err
			}
			if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM interface_role_overrides`).Scan(&overrides); err != nil {
				return err
			}
			wanted := 2
			if lane == 0 {
				wanted = 1
			}
			if policies != wanted || overrides != 1 {
				t.Fatal("role erasure changed unrelated configuration or sibling tenant", lane, policies, overrides)
			}
			var kept int
			if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM interface_role_policies WHERE tenant_id=$1 AND context_id=$2 AND id=$3`, tenant, unrelatedContext, otherPolicyID).Scan(&kept); err != nil {
				return err
			}
			if kept != 1 {
				t.Fatal("role erasure removed unrelated policy")
			}
			if lane == 1 {
				var body []byte
				if err := sc.Q.QueryRow(ctx, `SELECT definition FROM interface_role_policies WHERE tenant_id=$1 AND context_id=$2`, tenant, contextID).Scan(&body); err != nil {
					return err
				}
				var got entity.InterfaceRolePolicyDefinition
				if json.Unmarshal(body, &got) != nil || !reflect.DeepEqual(got, definition) {
					t.Fatal("role erasure altered sibling complete policy")
				}
			}
			if err := audit.LockTenantStream(ctx, sc.Q, tenant); err != nil {
				return err
			}
			generationErr := flowsnapshot.MatchSourceGenerationInScope(ctx, sc, generations[tenant])
			if (lane == 0) == (generationErr == nil) {
				t.Fatal("role subject erasure did not isolate source generation", lane, generationErr)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}
