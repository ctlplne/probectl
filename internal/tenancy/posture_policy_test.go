// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package tenancy

import (
	"os"
	"strings"
	"testing"
)

func TestStrictTenantPolicyExpression(t *testing.T) {
	tests := []struct {
		name string
		expr *string
		want bool
	}{
		{
			name: "postgres canonical strict equality",
			expr: policyExpr("(tenant_id = (NULLIF(current_setting('probectl.tenant_id'::text, true), ''::text))::uuid)"),
			want: true,
		},
		{
			name: "migration source strict equality",
			expr: policyExpr(" TENANT_ID = NULLIF(current_setting('probectl.tenant_id', true), '')::UUID "),
			want: true,
		},
		{
			name: "missing",
			expr: nil,
		},
		{
			name: "old unset GUC OR",
			expr: policyExpr("((NULLIF(current_setting('probectl.tenant_id'::text, true), ''::text) IS NULL) OR (tenant_id = (NULLIF(current_setting('probectl.tenant_id'::text, true), ''::text))::uuid))"),
		},
		{
			name: "coalesce unset GUC to row tenant",
			expr: policyExpr("tenant_id = COALESCE(NULLIF(current_setting('probectl.tenant_id', true), '')::uuid, tenant_id)"),
		},
		{
			name: "tautology whenever any tenant is set",
			expr: policyExpr("tenant_id = tenant_id AND current_setting('probectl.tenant_id', true) IS NOT NULL"),
		},
		{
			name: "extra conjunct",
			expr: policyExpr("tenant_id = NULLIF(current_setting('probectl.tenant_id', true), '')::uuid AND true"),
		},
		{
			name: "wrong setting",
			expr: policyExpr("tenant_id = NULLIF(current_setting('probectl.other_tenant_id', true), '')::uuid"),
		},
		{
			name: "unterminated literal",
			expr: policyExpr("tenant_id = current_setting('probectl.tenant_id, true)::uuid"),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := strictTenantPolicyExpression(tc.expr); got != tc.want {
				t.Fatalf("strictTenantPolicyExpression(%v) = %t, want %t", tc.expr, got, tc.want)
			}
		})
	}
}

func TestStrictSiloSchemaPolicyExpression(t *testing.T) {
	const tenantID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	tests := []struct {
		name string
		expr *string
		want bool
	}{
		{
			name: "postgres canonical schema and GUC equality",
			expr: policyExpr(
				"((tenant_id = '" + tenantID + "'::uuid) AND " +
					"(tenant_id = (NULLIF(current_setting('probectl.tenant_id'::text, true), ''::text))::uuid))",
			),
			want: true,
		},
		{
			name: "migration source schema and GUC equality",
			expr: policyExpr(
				"tenant_id = '" + tenantID + "'::uuid AND " +
					"tenant_id = NULLIF(current_setting('probectl.tenant_id', true), '')::uuid",
			),
			want: true,
		},
		{
			name: "missing",
			expr: nil,
		},
		{
			name: "GUC only",
			expr: policyExpr(
				"tenant_id = NULLIF(current_setting('probectl.tenant_id', true), '')::uuid",
			),
		},
		{
			name: "wrong physical schema tenant",
			expr: policyExpr(
				"tenant_id = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'::uuid AND " +
					"tenant_id = NULLIF(current_setting('probectl.tenant_id', true), '')::uuid",
			),
		},
		{
			name: "permissive OR shape",
			expr: policyExpr(
				"tenant_id = '" + tenantID + "'::uuid OR " +
					"tenant_id = NULLIF(current_setting('probectl.tenant_id', true), '')::uuid",
			),
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := strictSiloSchemaPolicyExpression(tc.expr, tenantID); got != tc.want {
				t.Fatalf(
					"strictSiloSchemaPolicyExpression(%v) = %t, want %t",
					tc.expr,
					got,
					tc.want,
				)
			}
		})
	}
}

func policyExpr(expr string) *string { return &expr }

// TestBreakGlassGrantsIsClassifiedProviderManaged (DPR-122) is the unit remnant
// of the former TestProviderPolicyQueryIsCatalogBasedAndPermissiveOnly: a
// genuine property over a package var — break_glass_grants, the provider-plane
// control table the privilege-filtered query once hid, must be classified as
// provider-managed with an explicit reason.
//
// The two behaviors that test used to grep posture.go's SQL for — the guard
// being catalog-based (pg_catalog.pg_attribute, not the privilege-filtered
// information_schema) and counting only PERMISSIVE policies as grants — are now
// exercised end to end against real catalogs by
// TestProviderPolicyGuardIsCatalogBasedAndPermissiveOnly in
// posture_providerpolicy_integration_test.go, which survives any reformat of the
// SQL and fails when either property is broken.
func TestBreakGlassGrantsIsClassifiedProviderManaged(t *testing.T) {
	reason, ok := providerManagedTables["break_glass_grants"]
	if !ok {
		t.Fatal("break_glass_grants must be classified: it carries a USING (true) provider policy")
	}
	if len(reason) < 40 {
		t.Errorf("the classification needs a real reason, got %q", reason)
	}
}

// TestAppGrantCheckNamesTheCauseNotJustTheSymptom (DPR-122): the failure this
// catches is a database whose tables carry policies for the application role
// and no privilege behind them, which happens when migrations run under a
// different role than the one that executed ALTER DEFAULT PRIVILEGES. The
// symptom an operator hits otherwise is a confusing isolation-posture error or
// a "permission denied" on an unrelated path, so the message has to carry the
// cause and the fix.
func TestAppGrantCheckNamesTheCauseNotJustTheSymptom(t *testing.T) {
	src, err := os.ReadFile("posture.go")
	if err != nil {
		t.Fatalf("read posture.go: %v", err)
	}
	q := string(src)
	start := strings.Index(q, "func assertAppGrantsMatchPolicies")
	if start < 0 {
		t.Fatal("assertAppGrantsMatchPolicies not found")
	}
	body := q[start:]
	if end := strings.Index(body[1:], "\nfunc "); end > 0 {
		body = body[:end]
	}
	// has_table_privilege is catalog truth: it does not depend on what the
	// connected role can see, which is the mistake the sibling check made.
	if !strings.Contains(body, "has_table_privilege('probectl_app'") {
		t.Error("the grant test must use has_table_privilege, not a privilege-filtered view")
	}
	if !strings.Contains(body, "p.permissive = 'PERMISSIVE'") {
		t.Error("only permissive policies imply the role is meant to use the table")
	}
	for _, want := range []string{"ALTER DEFAULT PRIVILEGES", "the role that RAN it", "refusing to start"} {
		if !strings.Contains(body, want) {
			t.Errorf("the refusal must explain the cause: missing %q", want)
		}
	}
	// And it must actually run at boot.
	if !strings.Contains(q, "return assertAppGrantsMatchPolicies(ctx, q)") {
		t.Error("the check must be part of the startup posture assertion")
	}
}

// TestAppGrantCheckExemptsProviderManagedTables (DPR-135): migration 0044 added
// a defense-in-depth tenant policy to break_glass_grants targeting the
// application role, which has no grant on the provider plane's break-glass
// ledger and must never be given one (§7.1). The grant check read that as a
// missing privilege and refused EVERY fresh install — and the only way to
// satisfy it would have been to hand the app role exactly the privilege the
// guardrail forbids. The exemption must come from providerManagedTables, so a
// new provider table is classified once and both checks agree.
func TestAppGrantCheckExemptsProviderManagedTables(t *testing.T) {
	if _, ok := providerManagedTables["break_glass_grants"]; !ok {
		t.Fatal("break_glass_grants must be classified as provider-managed")
	}
	src, err := os.ReadFile("posture.go")
	if err != nil {
		t.Fatalf("read posture.go: %v", err)
	}
	q := string(src)
	start := strings.Index(q, "func assertAppGrantsMatchPolicies")
	if start < 0 {
		t.Fatal("assertAppGrantsMatchPolicies not found")
	}
	body := q[start:]
	if end := strings.Index(body[1:], "\nfunc "); end > 0 {
		body = body[:end]
	}
	if !strings.Contains(body, "providerManagedTables[table]") {
		t.Error("the grant check must exempt provider-managed tables by consulting the classification, not a second hardcoded list")
	}
	// The exemption must be a skip, not a weakening of the refusal itself: a
	// non-provider table with a policy and no grant still has to fail.
	for _, want := range []string{"ALTER DEFAULT PRIVILEGES", "refusing to start"} {
		if !strings.Contains(body, want) {
			t.Errorf("the refusal for real cases must survive the exemption: missing %q", want)
		}
	}
}
