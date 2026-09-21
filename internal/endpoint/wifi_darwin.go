// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build darwin

package endpoint

import "context"

// airportBin is Apple's private Wi-Fi diagnostic tool; `-I` prints the current
// association report (RSSI/noise/SSID/channel/tx-rate).
const airportBin = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"

func newPlatformWiFiCollector() WiFiCollector {
	return cmdWiFiCollector{
		run:   func(ctx context.Context) (string, error) { return execText(ctx, airportBin, "-I") },
		parse: parseAirportI,
	}
}
