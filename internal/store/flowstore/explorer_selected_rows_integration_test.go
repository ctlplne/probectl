// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package flowstore

import (
	"fmt"
	"testing"
	"time"
)

func TestExplorerClickHouseCompleteRowsPastFormerQuotaKeepTenantTotals(t *testing.T) {
	store := explorerIntegrationStore(t)
	red := fmt.Sprintf("probectl-qa-beta-selected-red-%d", time.Now().UnixNano())
	blue := red + "-blue"
	t.Cleanup(func() {
		cleanupExplorerFixtureTenant(t, store, red)
		cleanupExplorerFixtureTenant(t, store, blue)
		_ = store.Close()
	})
	proveCompleteSelectedRowCapacity(t, store, red, blue)
}
