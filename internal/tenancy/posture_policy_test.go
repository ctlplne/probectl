// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package tenancy

import "testing"

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
