// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package flowstore

import "testing"

// Actual tenant-scoped ClickHouse reader/multipart lookup; projection inputs
// are modeled. Real sender and current Postgres authority are separate proofs.
func TestInterfaceRoleExplorerClickHouseKeepsTenantDirectionsAndCompleteTotals(t *testing.T) {
	store := explorerIntegrationStore(t)
	t.Cleanup(func() { _ = store.Close() })
	proveRoleExplorer(t, store, []string{"raw", "rollup"}, func(tenant string) { cleanupExplorerFixtureTenant(t, store, tenant) })
}
