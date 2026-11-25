// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build darwin && cgo

package endpoint

/*
#cgo LDFLAGS: -framework CoreWLAN -framework Foundation
#include "wifi_corewlan.h"
*/
import "C"

import (
	"context"
	"math"
)

type coreWLANCollector struct{ privacy Privacy }

func newPlatformWiFiCollector(privacy Privacy) WiFiCollector {
	return coreWLANCollector{privacy: privacy}
}

func (c coreWLANCollector) Collect(ctx context.Context) (WiFi, error) {
	if err := ctx.Err(); err != nil {
		return WiFi{}, err
	}
	var native C.probectl_wifi_link
	C.probectl_read_wifi_link(C.bool(c.privacy.CollectSSID), C.bool(c.privacy.CollectBSSID), &native)
	if err := ctx.Err(); err != nil {
		return WiFi{}, err
	}
	reading := coreWLANReading{
		present: bool(native.present), associated: bool(native.associated),
		band: uint8(native.band), channel: uint64(native.channel),
		rssi: int64(native.rssi), noise: int64(native.noise), rate: float64(native.rate),
		ssid: C.GoString(&native.ssid[0]), bssid: C.GoString(&native.bssid[0]),
	}
	return reading.sample(c.privacy), nil
}

type coreWLANReading struct {
	present    bool
	associated bool
	band       uint8
	channel    uint64
	rssi       int64
	noise      int64
	rate       float64
	ssid       string
	bssid      string
}

func (r coreWLANReading) sample(privacy Privacy) WiFi {
	wifi := WiFi{Present: r.present, Associated: r.present && r.associated}
	if !wifi.Associated {
		return wifi
	}
	if r.channel > 0 && r.channel <= 255 {
		wifi.Channel = int(r.channel)
	}
	switch r.band {
	case 2:
		wifi.Band = "2.4GHz"
	case 5:
		wifi.Band = "5GHz"
	case 6:
		wifi.Band = "6GHz"
	}
	// CoreWLAN reports zero when a measurement is unavailable.
	if r.rssi < 0 && r.rssi > -256 {
		wifi.RSSIDBm, wifi.Have.RSSI = float64(r.rssi), true
	}
	if r.noise < 0 && r.noise > -256 {
		wifi.NoiseDBm, wifi.Have.Noise = float64(r.noise), true
	}
	if r.rate > 0 && !math.IsInf(r.rate, 0) {
		wifi.LinkRateMbps, wifi.Have.LinkRate = r.rate, true
	}
	if privacy.CollectSSID {
		wifi.SSID = r.ssid
	}
	if privacy.CollectBSSID {
		wifi.BSSID = r.bssid
	}
	return wifi
}
