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
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	gouuid "github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/testsupport"
)

// Real application-role Postgres, handler authorization, lifecycle and atomic
// audit. Router telemetry is deliberately absent: manual configuration must
// not depend on a source clock or make an automatic source claim.
func TestInterfaceRoleConfigurationAPIKeepsCompletePoliciesTenantCASAndAtomicAudit(t *testing.T) {
	s, db := setupAPIServerWithLatest(t, nil)
	testsupport.LockPostgresPublicCatalog(t, db.Pool())
	tenants := []string{freshTenant(t, db, "roles-api-a"), freshTenant(t, db, "roles-api-b")}
	t.Cleanup(func() {
		if _, err := db.Pool().Exec(context.Background(), `DELETE FROM tenants WHERE id=ANY($1::uuid[])`, tenants); err != nil {
			t.Error(err)
		}
	})
	contextID, interfaceID, routerID, foreignContext := gouuid.NewString(), gouuid.NewString(), gouuid.NewString(), gouuid.NewString()
	for _, tenant := range tenants {
		if _, err := db.Pool().Exec(t.Context(), `INSERT INTO entity_contexts(tenant_id,id,site_id,vrf_id,site_label,vrf_label) VALUES($1,$2,$3,$4,'shared site','shared vrf')`, tenant, contextID, gouuid.NewString(), gouuid.NewString()); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Pool().Exec(t.Context(), `INSERT INTO entities(tenant_id,context_id,id,kind,label) VALUES($1,$2,$3,'device','router'),($1,$2,$4,'interface','uplink')`, tenant, contextID, routerID, interfaceID); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.Pool().Exec(t.Context(), `INSERT INTO entity_contexts(tenant_id,id,site_id,vrf_id,site_label,vrf_label) VALUES($1,$2,$3,$4,'foreign','foreign')`, tenants[1], foreignContext, gouuid.NewString(), gouuid.NewString()); err != nil {
		t.Fatal(err)
	}
	request := func(method, path, tenant string, input any, withheld string) *httptest.ResponseRecorder {
		t.Helper()
		body := ""
		if input != nil {
			raw, err := json.Marshal(input)
			if err != nil {
				t.Fatal(err)
			}
			body = string(raw)
		}
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("X-Probectl-Tenant", tenant)
		r.Header.Set("Content-Type", "application/json")
		if withheld != "" {
			r.Header.Set(testWithholdPermissionsHeader, withheld)
		}
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		return w
	}
	policyPath := "/v1/entity-contexts/" + contextID + "/interface-role-policy"
	overridePath := "/v1/entity-contexts/" + contextID + "/interfaces/" + interfaceID + "/role-override"
	policies := map[string]entity.InterfaceRolePolicyRecord{}
	overrides := map[string]entity.InterfaceRoleOverrideRecord{}
	for lane, tenant := range tenants {
		definition := entity.InterfaceRolePolicyDefinition{ProviderASNs: []uint32{uint32(64500 + lane)}, CustomerASNs: []uint32{}, DescriptionRules: []entity.InterfaceRoleDescriptionRule{}}
		for i := 0; i < 4097; i++ {
			definition.DescriptionRules = append(definition.DescriptionRules, entity.InterfaceRoleDescriptionRule{Pattern: "^" + tenant + strings.Repeat("-uplink", 25) + fmt.Sprint(i) + "$", Role: entity.InterfaceRoleBackbone})
		}
		input := interfaceRolePolicyInput{ExpectedRevision: "0", Definition: &definition}
		raw, _ := json.Marshal(input)
		if len(raw) <= 1<<20 {
			t.Fatal("complete policy fixture lost its large input population")
		}
		w := request(http.MethodPut, policyPath, tenant, input, "")
		var current entity.InterfaceRolePolicyRecord
		if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &current) != nil || len(current.Definition.DescriptionRules) != 4097 || current.TenantID != tenant || current.ID == "" || current.Revision != "1" {
			t.Fatalf("complete owned role policy was not published: %d %s", w.Code, w.Body.String())
		}
		for i, rule := range current.Definition.DescriptionRules {
			if rule.Pattern != definition.DescriptionRules[i].Pattern || rule.ID == "" {
				t.Fatal("complete policy lost rule order, value or server identity")
			}
		}
		// A semantically unchanged publication must remain editable under the same
		// default profile, including the retained old complete definition.
		unchanged := request(http.MethodPut, policyPath, tenant, interfaceRolePolicyInput{ExpectedID: current.ID, ExpectedRevision: current.Revision, Definition: &current.Definition}, "")
		var same entity.InterfaceRolePolicyRecord
		if unchanged.Code != http.StatusOK || json.Unmarshal(unchanged.Body.Bytes(), &same) != nil || same.ID != current.ID || same.Revision != current.Revision || !same.UpdatedAt.Equal(current.UpdatedAt) {
			t.Fatal("complete policy no-op failed or changed its semantic revision", unchanged.Code)
		}
		policies[tenant] = current
		w = request(http.MethodGet, policyPath, tenant, nil, "")
		if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), tenant) || strings.Contains(w.Body.String(), tenants[1-lane]) {
			t.Fatal("role policy read crossed tenant or lost complete body", w.Code)
		}
		w = request(http.MethodPut, overridePath, tenant, interfaceRoleOverrideInput{ExpectedRevision: "0", Role: entity.InterfaceRoleCustomer}, "")
		var override entity.InterfaceRoleOverrideRecord
		if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &override) != nil || override.TenantID != tenant || override.Role != entity.InterfaceRoleCustomer || override.ID == "" {
			t.Fatal("manual override required telemetry or escaped ownership", w.Code)
		}
		overrides[tenant] = override
		if got := request(http.MethodGet, overridePath, tenant, nil, ""); got.Code != http.StatusOK {
			t.Fatal("owned override unreadable without source", got.Code)
		}
	}
	firstDefinition := policies[tenants[0]].Definition
	for _, tc := range []struct {
		method, path, grant string
		input               any
	}{
		{http.MethodGet, policyPath, "entities.read", nil}, {http.MethodPut, policyPath, "agent.write", interfaceRolePolicyInput{ExpectedRevision: "0", Definition: &firstDefinition}},
		{http.MethodGet, overridePath, "entities.read", nil}, {http.MethodPut, overridePath, "agent.write", interfaceRoleOverrideInput{ExpectedRevision: "0", Role: entity.InterfaceRoleTransit}},
		{http.MethodDelete, overridePath, "agent.write", interfaceRoleResetInput{ExpectedID: overrides[tenants[0]].ID, ExpectedRevision: "1", Confirmed: true}},
	} {
		for _, tenant := range tenants {
			if got := request(tc.method, tc.path, tenant, tc.input, tc.grant); got.Code != http.StatusForbidden {
				t.Fatal("configuration route ignored read/write boundary", tc.method, got.Code)
			}
		}
	}
	foreignPath := "/v1/entity-contexts/" + foreignContext + "/interface-role-policy"
	if got := request(http.MethodGet, foreignPath, tenants[0], nil, ""); got.Code != http.StatusNotFound {
		t.Fatal("foreign role context was observable", got.Code)
	}
	wrongKind := "/v1/entity-contexts/" + contextID + "/interfaces/" + routerID + "/role-override"
	if got := request(http.MethodPut, wrongKind, tenants[0], interfaceRoleOverrideInput{ExpectedRevision: "0", Role: entity.InterfaceRoleTransit}, ""); got.Code != http.StatusNotFound {
		t.Fatal("role override admitted a non-interface", got.Code)
	}
	for _, tenant := range tenants {
		old := overrides[tenant]
		if got := request(http.MethodDelete, overridePath, tenant, interfaceRoleResetInput{ExpectedID: old.ID, ExpectedRevision: old.Revision}, ""); got.Code != http.StatusBadRequest {
			t.Fatal("unconfirmed reset succeeded", got.Code)
		}
		if got := request(http.MethodDelete, overridePath, tenant, interfaceRoleResetInput{ExpectedID: old.ID, ExpectedRevision: old.Revision, Confirmed: true}, ""); got.Code != http.StatusNoContent {
			t.Fatal("owned confirmed reset failed", got.Code)
		}
		if got := request(http.MethodPut, overridePath, tenant, interfaceRoleOverrideInput{ExpectedRevision: "0", Role: entity.InterfaceRoleBackbone}, ""); got.Code != http.StatusOK {
			t.Fatal("override recreation failed", got.Code)
		}
		if got := request(http.MethodPut, overridePath, tenant, interfaceRoleOverrideInput{ExpectedID: old.ID, ExpectedRevision: old.Revision, Role: entity.InterfaceRoleTransit}, ""); got.Code != http.StatusConflict {
			t.Fatal("stale override edited a recreated configuration", got.Code)
		}
		if got := request(http.MethodDelete, overridePath, tenant, interfaceRoleResetInput{ExpectedID: old.ID, ExpectedRevision: old.Revision, Confirmed: true}, ""); got.Code != http.StatusConflict {
			t.Fatal("stale override reset a recreated configuration", got.Code)
		}
	}
	old := policies[tenants[0]]
	smaller := flowstore.DefaultExplorerBudget()
	smaller.MemoryBytes = 1 << 20
	if err := flowstore.AttachExplorerBudget(s.flowStore, smaller); err != nil {
		t.Fatal(err)
	}
	if got := request(http.MethodGet, policyPath, tenants[0], nil, ""); got.Code != http.StatusTooManyRequests {
		t.Fatal("lower operation profile returned a partial policy", got.Code)
	}
	if err := flowstore.AttachExplorerBudget(s.flowStore, flowstore.DefaultExplorerBudget()); err != nil {
		t.Fatal(err)
	}
	originalABAC := s.abac
	s.abac = &abacCache{load: func(_ context.Context, tenant string) ([]auth.Policy, error) {
		if tenant == tenants[0] {
			return []auth.Policy{{Name: "deny current role configuration", Enabled: true, Effect: auth.PolicyDeny, Permission: "entities.read", Resource: map[string]string{"site_label": "shared site"}}}, nil
		}
		return nil, nil
	}}
	if got := request(http.MethodGet, policyPath, tenants[0], nil, ""); got.Code != http.StatusForbidden {
		t.Fatal("configuration read ignored current context ABAC", got.Code)
	}
	s.abac = originalABAC
	// A domain-audit fault must roll back the mutation and exact version.
	fault := "probectl_qa_beta_role_audit_" + strings.ReplaceAll(gouuid.NewString(), "-", "")
	if _, err := db.Pool().Exec(t.Context(), `CREATE FUNCTION public.`+fault+`() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.tenant_id='`+tenants[0]+`'::uuid AND NEW.action LIKE 'interface.role.%' THEN RAISE EXCEPTION 'owned QA role audit refused'; END IF; RETURN NEW; END $$; CREATE TRIGGER `+fault+` BEFORE INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION public.`+fault+`()`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := db.Pool().Exec(context.Background(), `DROP TRIGGER IF EXISTS `+fault+` ON audit_events; DROP FUNCTION IF EXISTS public.`+fault+`()`); err != nil {
			t.Error(err)
		}
	})
	changed := old.Definition
	changed.ProviderASNs = []uint32{64496}
	if got := request(http.MethodPut, policyPath, tenants[0], interfaceRolePolicyInput{ExpectedID: old.ID, ExpectedRevision: old.Revision, Definition: &changed}, ""); got.Code < 500 {
		t.Fatal("audit refusal did not fail the write", got.Code)
	}
	var stored string
	if err := db.Pool().QueryRow(t.Context(), `SELECT revision::text FROM interface_role_policies WHERE tenant_id=$1 AND context_id=$2`, tenants[0], contextID).Scan(&stored); err != nil || stored != old.Revision {
		t.Fatal("audit refusal committed role configuration revision", err)
	}
	afterRead := request(http.MethodGet, policyPath, tenants[0], nil, "")
	var afterPolicy entity.InterfaceRolePolicyRecord
	if afterRead.Code != http.StatusOK || json.Unmarshal(afterRead.Body.Bytes(), &afterPolicy) != nil || !reflect.DeepEqual(afterPolicy, old) {
		t.Fatal("audit refusal committed the new policy body or its identity/version", afterRead.Code)
	}
}
