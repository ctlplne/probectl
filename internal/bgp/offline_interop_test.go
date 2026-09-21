// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package bgp

import (
	"os"
	"testing"
)

func TestOfflineInteropBGPAnalyzerBridgeTenantScoped(t *testing.T) {
	if _, err := os.ReadFile("../../test/interop/fixtures/bgp-mrt.json"); err != nil {
		t.Fatal(err)
	}
	TestBridgePublishesTenantKeyedEvent(t)
}
