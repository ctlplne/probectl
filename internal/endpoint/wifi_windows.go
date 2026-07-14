// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//go:build windows

package endpoint

import "context"

func newPlatformWiFiCollector() WiFiCollector {
	return cmdWiFiCollector{
		run:   func(ctx context.Context) (string, error) { return execText(ctx, "netsh", "wlan", "show", "interfaces") },
		parse: parseNetshWlan,
	}
}
