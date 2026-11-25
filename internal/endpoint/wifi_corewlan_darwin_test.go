// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build darwin && cgo

package endpoint

import (
	"context"
	"errors"
	"math"
	"testing"
)

func TestCoreWLANConsentAndPrivacyPreserveLinkMeasurements(t *testing.T) {
	reading := coreWLANReading{present: true, associated: true, channel: 5, band: 6, rssi: -58, noise: -94, rate: 866}
	link := reading.sample(DefaultPrivacy())
	if !link.Present || !link.Associated || link.SSID != "" || link.BSSID != "" ||
		link.Channel != 5 || link.Band != "6GHz" || !link.Have.RSSI || link.RSSIDBm != -58 ||
		!link.Have.Noise || link.NoiseDBm != -94 || !link.Have.LinkRate || link.LinkRateMbps != 866 {
		t.Fatal("missing location identifiers discarded measurements or misclassified a low 6 GHz channel", link)
	}
	reading.ssid, reading.bssid = "local-fixture", "00:11:22:33:44:55"
	if got := reading.sample(strictPrivacy()); got != link {
		t.Fatal("strict mode changed measurements or exposed identifiers", got)
	}
	balanced := reading.sample(DefaultPrivacy())
	if balanced.SSID != "local-fixture" || balanced.BSSID != "" {
		t.Fatal("balanced mode did not keep the SSID alone", balanced)
	}
	bssidOptIn := reading.sample(Privacy{CollectBSSID: true})
	if bssidOptIn.SSID != "" || bssidOptIn.BSSID != "00:11:22:33:44:55" {
		t.Fatal("BSSID opt-in bypassed the independent SSID policy", bssidOptIn)
	}
	reading.rssi, reading.noise, reading.rate, reading.channel = 0, -256, math.Inf(1), ^uint64(0)
	if got := reading.sample(strictPrivacy()); got.Have != (WiFiHave{}) || got.Channel != 0 {
		t.Fatal("an unavailable measurement became valid", got)
	}
	reading.associated = false
	if got := reading.sample(DefaultPrivacy()); got != (WiFi{Present: true}) {
		t.Fatal("a disconnected interface exposed a stale sample", got)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := newPlatformWiFiCollector(DefaultPrivacy()).Collect(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled collection did not stop before CoreWLAN", err)
	}
}
