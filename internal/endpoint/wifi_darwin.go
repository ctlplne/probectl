// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

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
