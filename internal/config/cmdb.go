// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package config

import "github.com/ctlplne/probectl/internal/cmdb"

func (l *loader) netBoxTenantMap() map[string]string {
	const key = "PROBECTL_CMDB_NETBOX_TENANT_MAP"
	bindings, err := cmdb.ParseNetBoxTenantMap(l.getenv(key))
	if err != nil {
		l.errf("%s must map canonical tenant UUIDs to distinct positive NetBox tenant ID strings", key)
	}
	return bindings
}
