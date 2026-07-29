// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package tenancy

import "testing"

func TestStrictTenantPolicyExpression(t *testing.T) {
	strict := "(tenant_id = (NULLIF(current_setting('probectl.tenant_id'::text, true), ''::text))::uuid)"
	failOpen := "((NULLIF(current_setting('probectl.tenant_id'::text, true), ''::text) IS NULL) OR (tenant_id = (NULLIF(current_setting('probectl.tenant_id'::text, true), ''::text))::uuid))"

	if !strictTenantPolicyExpression(&strict) {
		t.Fatal("strict tenant equality was rejected")
	}
	if strictTenantPolicyExpression(&failOpen) {
		t.Fatal("unset-GUC allow-all expression was accepted")
	}
	if strictTenantPolicyExpression(nil) {
		t.Fatal("missing policy expression was accepted")
	}
}
