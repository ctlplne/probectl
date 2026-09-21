// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package chclient

import "fmt"

// ReaderRowPolicyDDL returns the convergent DDL for one setting-scoped reader
// policy. Callers must validate every identifier before calling it.
//
// OR REPLACE is the security boundary here: IF NOT EXISTS would leave a fixed
// policy attached to the previous reader after credential rotation, while the
// new reader could issue unfiltered SELECTs.
func ReaderRowPolicyDDL(policy, table, tenantSetting, readerUser string) string {
	return fmt.Sprintf(
		"CREATE ROW POLICY OR REPLACE %s ON %s FOR SELECT USING tenant_id = getSetting('%s') TO %s",
		policy, table, tenantSetting, readerUser,
	)
}
