// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package endpoint

import (
	"strings"
	"testing"
)

func fullSample() Sample {
	return Sample{
		WiFi:    WiFi{Present: true, Associated: true, SSID: "home-net", BSSID: "aa:bb:cc:dd:ee:ff", RSSIDBm: -60, Have: WiFiHave{RSSI: true}},
		Gateway: Gateway{IP: "192.168.1.1", Reachable: true, RTTMs: 3},
		LastMile: LastMile{Hops: []LastMileHop{
			{Index: 1, IP: "192.168.1.1", Private: true, RTTMs: 3},
			{Index: 2, IP: "203.0.113.7", Private: false, RTTMs: 15, LossPct: 1},
		}},
	}
}

// TestPrivacyDefaultScoping is the privacy-config scoping test: the default
// posture drops the geolocatable BSSID and the public-hop IP, while KEEPING the
// measurements (RTT/loss) and the low-sensitivity SSID/gateway.
func TestPrivacyDefaultScoping(t *testing.T) {
	s := fullSample()
	DefaultPrivacy().Apply(&s)

	if s.WiFi.BSSID != "" {
		t.Errorf("default privacy must drop BSSID, got %q", s.WiFi.BSSID)
	}
	if s.WiFi.SSID != "home-net" {
		t.Errorf("default privacy keeps SSID, got %q", s.WiFi.SSID)
	}
	if s.Gateway.IP != "192.168.1.1" {
		t.Errorf("default privacy keeps the (private) gateway IP, got %q", s.Gateway.IP)
	}
	// Public hop: IP dropped, RTT/loss measurement preserved.
	pub := s.LastMile.Hops[1]
	if pub.IP != "" {
		t.Errorf("default privacy must drop the public hop IP, got %q", pub.IP)
	}
	if pub.RTTMs != 15 || pub.LossPct != 1 {
		t.Errorf("measurements must be preserved, got rtt=%v loss=%v", pub.RTTMs, pub.LossPct)
	}
	// Private hop IP is kept (it's inside the user's LAN, not identifying externally).
	if s.LastMile.Hops[0].IP != "192.168.1.1" {
		t.Errorf("private hop IP should be kept, got %q", s.LastMile.Hops[0].IP)
	}
}

func TestStrictPrivacyDropsAllIdentifiers(t *testing.T) {
	s := fullSample()
	strictPrivacy().Apply(&s)
	if s.WiFi.SSID != "" || s.WiFi.BSSID != "" || s.Gateway.IP != "" {
		t.Errorf("strict privacy must drop every identifier, got ssid=%q bssid=%q gw=%q", s.WiFi.SSID, s.WiFi.BSSID, s.Gateway.IP)
	}
	if s.LastMile.Hops[1].IP != "" {
		t.Errorf("strict privacy must drop public hop IPs")
	}
	// But the RSSI measurement is still there.
	if !s.WiFi.Have.RSSI || s.WiFi.RSSIDBm != -60 {
		t.Errorf("strict privacy must keep measurements")
	}
}

func TestPrivacyCollectAllKeepsEverything(t *testing.T) {
	s := fullSample()
	Privacy{CollectSSID: true, CollectBSSID: true, CollectGatewayIP: true, CollectPublicHops: true}.Apply(&s)
	if s.WiFi.BSSID == "" || s.LastMile.Hops[1].IP == "" {
		t.Errorf("collect-all should keep BSSID and public hop IPs")
	}
}

func TestDisclosure(t *testing.T) {
	d := DefaultPrivacy().Disclosure()
	joined := strings.Join(d, "\n")
	if !strings.Contains(joined, "access-point MAC (BSSID): NOT collected") {
		t.Errorf("default disclosure should state BSSID is not collected:\n%s", joined)
	}
	if !strings.Contains(joined, "WiFi network name (SSID): collected") {
		t.Errorf("default disclosure should state SSID is collected:\n%s", joined)
	}
}
