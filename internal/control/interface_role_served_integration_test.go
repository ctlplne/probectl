// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package control

import (
	"context"
	"encoding/pem"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"testing"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport"
)

// Drives the production admin page under real sessions and PostgreSQL RLS.
// The evidence writer uses modeled device observations here. Physical device
// and router transport have separate real-stack tests.
func TestInterfaceRoleAdminServedKeepsTenantWritesAndBothThemes(t *testing.T) {
	f := newRoleExplanationAPIFixture(t)
	configuration := store.InterfaceRoleConfiguration{}
	policies := make([]entity.InterfaceRolePolicyRecord, len(f.tenants))
	overrides := make([]entity.InterfaceRoleOverrideRecord, len(f.tenants))
	cookies := make([]string, len(f.tenants))
	for lane, tenant := range f.tenants {
		var grants []auth.PermissionGrant
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			old, err := configuration.Policy(ctx, sc, f.contextID, roleExplanationStoreBudget())
			if err != nil {
				return err
			}
			for i := range 31 {
				old.Definition.DescriptionRules = append(old.Definition.DescriptionRules, entity.InterfaceRoleDescriptionRule{
					Pattern: fmt.Sprintf("^lane-%d-rule-%d$", lane, i), Role: entity.InterfaceRoleBackbone,
				})
			}
			policies[lane], err = configuration.PutPolicy(ctx, sc, f.contextID, old.ID, old.Revision, old.Definition, roleExplanationStoreBudget())
			if err != nil {
				return err
			}
			overrides[lane], err = configuration.PutOverride(ctx, sc, f.contextID, f.interfaceID, "", "0", entity.InterfaceRoleCustomer)
			if err != nil {
				return err
			}
			grants, err = (store.Permissions{}).ForSubject(ctx, sc, "user", f.users[tenant])
			return err
		})
		cookie, err := f.server.sessions.Issue(t.Context(), auth.Session{TenantID: tenant, UserID: f.users[tenant], Email: "roles@local.invalid", DisplayName: "Interface operator", MFASatisfied: true, AuthorizationHash: auth.PermissionGrantFingerprint(grants)})
		if err != nil {
			t.Fatal(err)
		}
		cookies[lane] = cookie
	}
	socket := httptest.NewTLSServer(f.server.Handler())
	t.Cleanup(socket.Close)
	ca := filepath.Join(t.TempDir(), "served-ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: socket.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	read := func(t *testing.T, lane int) (policy entity.InterfaceRolePolicyRecord, override entity.InterfaceRoleOverrideRecord) {
		t.Helper()
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(f.tenants[lane]))
		err := tenancy.InTenantReadSnapshot(ctx, f.pool, func(ctx context.Context, sc tenancy.Scope) error {
			var err error
			policy, err = configuration.Policy(ctx, sc, f.contextID, roleExplanationStoreBudget())
			if err != nil {
				return err
			}
			override, err = configuration.Override(ctx, sc, f.contextID, f.interfaceID)
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
		return policy, override
	}
	for lane := range f.tenants {
		for _, theme := range []string{"light", "dark"} {
			t.Run(strconv.Itoa(lane)+"/"+theme, func(t *testing.T) {
				const card = "[data-interface-roles]"
				const current = "[aria-label='Current interface role']"
				const overrideReady = card + ` form:has(label:text-is("Manual interface role") + div select option[value="backbone"]:checked)`
				selector := func(label, tag string) string {
					return card + " label:text-is(" + strconv.Quote(label) + ") + div " + tag
				}
				pattern := fmt.Sprintf("^lane-%d-edit-%s$", lane, theme)
				own := "policy/" + policies[lane].ID + "/"
				foreign := "policy/" + policies[1-lane].ID + "/"
				before := []string{"transit", "current evidence", own}
				if overrides[lane].Role != "" {
					before = []string{string(overrides[lane].Role), "operator override", overrides[lane].ID}
				}
				testsupport.RenderUI(t, testsupport.RenderSpec{
					URL: socket.URL + "/ui/admin", Cookies: []testsupport.RenderCookie{{Name: auth.SessionCookie, Value: cookies[lane]}},
					TrustCertFiles: []string{ca}, CAFile: ca, Theme: theme, Accessibility: true, TimeoutMs: 90000,
					Expect: []string{"Interface roles"}, Absent: []string{foreign, "The override changed. Reload before editing or resetting it."},
					Steps: []testsupport.RenderStep{
						{Select: selector("Interface role routing context", "select"), Value: f.contextID},
						{Click: "Next role rules", Within: card, Expect: []string{"31 description rules; page 2 of 2."}},
						{Fill: selector("Description pattern 31", "input"), Value: pattern},
						{Click: "Save complete role policy", Within: card, Expect: []string{"Complete role policy saved."}},
						{Select: selector("Interface for role explanation and override", "select"), Value: f.interfaceID},
						{Click: "Refresh role explanation", Within: current, ExpectWithin: current, Expect: before},
						{Select: selector("Manual interface role", "select"), Value: string(entity.InterfaceRoleBackbone)},
						{Click: "Save manual role override", Within: overrideReady, ExpectWithin: current, Expect: []string{"backbone", "operator override"}},
						{Click: "Reset manual role override", Within: card, Expect: []string{"Reset manual interface role?"}},
						{Click: "Confirm role reset", Within: "[role='dialog']", Gone: true, ExpectWithin: current, Expect: []string{"transit", "current evidence", own}},
					},
				})
				updated, reset := read(t, lane)
				expected := policies[lane].Definition
				expected.DescriptionRules = append([]entity.InterfaceRoleDescriptionRule(nil), expected.DescriptionRules...)
				expected.DescriptionRules[30].Pattern = pattern
				if updated.ID != policies[lane].ID || updated.Revision == policies[lane].Revision || !reflect.DeepEqual(updated.Definition, expected) || reset.ID != "" || reset.Revision != "0" || reset.Role != "" {
					t.Fatal("served policy write or confirmed reset lost current configuration")
				}
				sibling, siblingOverride := read(t, 1-lane)
				if !reflect.DeepEqual(sibling, policies[1-lane]) || siblingOverride != overrides[1-lane] {
					t.Fatal("served write or reset changed the sibling tenant's same-ID interface")
				}
				policies[lane], overrides[lane] = updated, reset
			})
		}
	}
}
