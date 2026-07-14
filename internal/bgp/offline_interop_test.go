// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

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
