// SPDX-License-Identifier: LicenseRef-probectl-TBD

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
