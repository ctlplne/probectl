// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//go:build !linux && !darwin && !windows

package endpoint

import "context"

// unsupportedWiFi is the fallback on platforms with no Wi-Fi reader. It reports
// "no Wi-Fi present" so the rest of the sample (gateway/last-mile/sessions) still
// forms and attribution simply skips the Wi-Fi layer (graceful degradation).
type unsupportedWiFi struct{}

func (unsupportedWiFi) Collect(context.Context) (WiFi, error) { return WiFi{}, nil }

func newPlatformWiFiCollector() WiFiCollector { return unsupportedWiFi{} }
