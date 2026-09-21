// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build linux

package endpoint

import (
	"context"
	"os"
)

// linuxWiFi reads the Wi-Fi link on Linux: NetworkManager (nmcli) first — present
// on most laptops and richest — falling back to the dependency-free
// /proc/net/wireless when nmcli is unavailable (minimal/headless hosts).
type linuxWiFi struct{}

func (linuxWiFi) Collect(ctx context.Context) (WiFi, error) {
	if out, err := execText(ctx, "nmcli", "-t", "-f", "ACTIVE,SSID,BSSID,CHAN,FREQ,RATE,SIGNAL", "dev", "wifi"); err == nil {
		if w := parseNmcli(out); w.Associated {
			return w, nil
		}
	}
	if b, err := os.ReadFile("/proc/net/wireless"); err == nil {
		return parseProcNetWireless(string(b)), nil
	}
	return WiFi{}, nil // no Wi-Fi tooling: degrade (Present=false)
}

func newPlatformWiFiCollector() WiFiCollector { return linuxWiFi{} }
