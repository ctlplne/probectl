// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package chclient

import (
	"fmt"
	"strings"
)

// ReaderRowPolicyStatements returns the convergent DDL for one setting-scoped
// reader policy, in order. Callers must validate every identifier first.
//
// DPR-325: the policy must stay in place WHILE it is converged. ClickHouse
// runs CREATE ROW POLICY OR REPLACE as remove-then-insert, and its row-policy
// cache sees the two separately: a reader query that starts in between finds
// no policy on the table and, under the default
// users_without_row_policies_can_read_rows=true, reads every row. That
// happened on every boot of every replica (measured: 291 of 17,685
// concurrent foreign-tenant reads unfiltered). Instead:
//
//  1. CREATE ROW POLICY IF NOT EXISTS installs the policy when it is absent
//     and is a no-op otherwise, never removing an existing one;
//  2. ALTER ROW POLICY then converges an existing policy's expression and
//     binding in place. It is the step that matters after a credential
//     rotation: IF NOT EXISTS alone would leave a fixed policy name bound to
//     the previous reader while the new reader issued unfiltered SELECTs.
func ReaderRowPolicyStatements(policy, table, tenantSetting, readerUser string) []string {
	body := fmt.Sprintf("%s ON %s FOR SELECT USING tenant_id = getSetting('%s') TO %s", policy, table, tenantSetting, QuotePolicyUser(readerUser))
	return []string{
		"CREATE ROW POLICY IF NOT EXISTS " + body,
		"ALTER ROW POLICY " + body,
	}
}

// QuotePolicyUser renders a ClickHouse account name as one quoted identifier.
// Policy and grant callers must still validate the supported username shape before issuing DDL.
// Quoting preserves hyphenated and digit-leading names and prevents names such
// as ALL from being interpreted as role-set syntax. It grants no privileges.
func QuotePolicyUser(user string) string {
	return "`" + strings.NewReplacer("\\", "\\\\", "`", "\\`").Replace(user) + "`"
}
