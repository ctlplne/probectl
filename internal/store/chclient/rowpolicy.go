// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

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
