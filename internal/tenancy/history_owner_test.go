// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package tenancy

import (
	"strings"
	"testing"
)

func TestHistoryOwnerPredicateExactGroupingNeverWidensTenant(t *testing.T) {
	for _, expr := range []string{FlowHistoryOwnerPredicate, postgresHistoryOwnerPredicate, strings.ReplaceAll(postgresHistoryOwnerPredicate, " AND ", "\n AnD \t")} {
		if !exactHistoryOwnerExpression(&expr) {
			t.Fatal("exact owner predicate refused")
		}
	}
	regrouped := `(tenant_id = NULLIF(current_setting('probectl.tenant_id', true), '')::uuid
        AND owner_id = NULLIF(current_setting('probectl.flow_history_owner', true), '')::uuid)
        OR current_setting('probectl.flow_history_lifecycle', true) = 'authorized'`
	for _, expr := range []string{
		regrouped,
		FlowHistoryOwnerPredicate + ` OR true`,
		FlowHistoryOwnerPredicate + ` AND false`,
		strings.ReplaceAll(FlowHistoryOwnerPredicate, "flow_history_owner", "other_owner"),
		strings.ReplaceAll(FlowHistoryOwnerPredicate, "'authorized'", "'AUTHORIZED'"),
		strings.ReplaceAll(FlowHistoryOwnerPredicate, "::uuid", "::text"),
		`true`, `owner_id=owner_id`, `'unterminated`,
	} {
		if exactHistoryOwnerExpression(&expr) {
			t.Fatal("owner posture accepted a widened/changed predicate")
		}
	}
	if exactHistoryOwnerExpression(nil) {
		t.Fatal("missing owner predicate accepted")
	}
	a, _ := normalizeTenantPolicyExpression(FlowHistoryOwnerPredicate)
	b, _ := normalizeTenantPolicyExpression(regrouped)
	if a != b {
		t.Fatal("regrouping probe no longer defeats the old conjunction-only normalizer")
	}
}
