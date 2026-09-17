// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

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

// TestProviderPolicyQueryIsCatalogBasedAndPermissiveOnly (DPR-122): two
// properties of the query itself, because both defects it had were invisible
// in its result rather than in its logic.
//
//   - The tenant_id test must read the CATALOG. information_schema.columns is
//     filtered by the connected role's privileges, so a table the app role had
//     no grant on simply did not exist as far as this guard was concerned —
//     on the QA lab that hid break_glass_grants and its `USING (true)`
//     provider policy, which is the exact shape the guard refuses.
//   - Only PERMISSIVE policies grant. A RESTRICTIVE policy constrains what a
//     permissive one allows, so counting one as an unconstrained grant would
//     refuse to start on a database that is MORE locked down.
func TestProviderPolicyQueryIsCatalogBasedAndPermissiveOnly(t *testing.T) {
	src, err := os.ReadFile("posture.go")
	if err != nil {
		t.Fatalf("read posture.go: %v", err)
	}
	q := string(src)
	start := strings.Index(q, "func assertProviderPoliciesAreScoped")
	if start < 0 {
		t.Fatal("assertProviderPoliciesAreScoped not found")
	}
	body := q[start:]
	if end := strings.Index(body, "\nfunc "); end > 0 {
		body = body[:end]
	}
	// Only the SQL matters here, not the comment that explains it: the query
	// is the argument to Query(, so start there.
	call := strings.Index(body, "q.Query(ctx, `")
	if call < 0 {
		t.Fatal("the provider-policy query was not found")
	}
	body = body[call:]
	if end := strings.Index(body[len("q.Query(ctx, `"):], "`"); end > 0 {
		body = body[:len("q.Query(ctx, `")+end]
	}
	if strings.Contains(body, "information_schema.columns") {
		t.Error("the tenant_id test must not use information_schema: it is filtered by the connected role's privileges")
	}
	for _, want := range []string{"pg_catalog.pg_attribute", "p.permissive = 'PERMISSIVE'"} {
		if !strings.Contains(body, want) {
			t.Errorf("the provider-policy query must contain %q", want)
		}
	}
	// break_glass_grants is the table the privilege-filtered query hid; it is
	// provider-plane control state and must carry an explicit reason.
	reason, ok := providerManagedTables["break_glass_grants"]
	if !ok {
		t.Fatal("break_glass_grants must be classified: it carries a USING (true) provider policy")
	}
	if len(reason) < 40 {
		t.Errorf("the classification needs a real reason, got %q", reason)
	}
}
