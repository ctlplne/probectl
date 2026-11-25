// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package nmsimport

import (
	"errors"
	"strings"
	"testing"
)

func TestDiscoveryInventoryNormalizesDeviceRows(t *testing.T) {
	snapshot, err := discoverySnapshot([]DiscoveryDevice{
		{ExternalID: "first", Hostname: "Router.Lab.", Address: "::ffff:192.0.2.9"},
		{ExternalID: "second", Hostname: "https://display.invalid/", Address: "fe80::1%eth0"},
		{ExternalID: "third", Address: "192.0.2.10"},
	})
	if err != nil {
		t.Fatal(err)
	}
	rows, err := normalizePlanPage("00000000-0000-4000-8000-000000000001", "20000000-0000-4000-8000-000000000001",
		"fixture", strings.Repeat("a", 64), DeviceDiscovery, snapshot, 0)
	if err != nil || len(rows) != 3 || rows[0].Hostname != "router.lab" || rows[0].Address != "192.0.2.9" ||
		rows[0].ReviewOnly || rows[1].Hostname != "" || rows[1].Label != "" || rows[1].Address != "" || !rows[1].ReviewOnly ||
		rows[2].Label != "192.0.2.10" || rows[2].ReviewOnly {
		t.Fatal("device discovery fields were not normalized and held for review", err)
	}
	if _, err := discoverySnapshot([]DiscoveryDevice{{ExternalID: "unsafe\nsource-id"}}); !errors.Is(err, ErrInvalidPage) {
		t.Fatal("unsafe device identity was accepted", err)
	}
}
