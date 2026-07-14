// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package endpoint

import "testing"

func TestParseAirportI(t *testing.T) {
	out := `     agrCtlRSSI: -58
     agrExtRSSI: 0
    agrCtlNoise: -92
    agrExtNoise: 0
          state: running
        op mode: station
      lastTxRate: 866
          maxRate: 1300
            BSSID: a1:b2:c3:d4:e5:f6
             SSID: CorpWiFi
              MCS: 9
        channel: 36,80`
	w := parseAirportI(out)
	if !w.Present || !w.Associated {
		t.Fatalf("should be present+associated: %+v", w)
	}
	if !w.Have.RSSI || w.RSSIDBm != -58 {
		t.Errorf("RSSI = %v (have=%v), want -58", w.RSSIDBm, w.Have.RSSI)
	}
	if !w.Have.Noise || w.NoiseDBm != -92 {
		t.Errorf("noise = %v, want -92", w.NoiseDBm)
	}
	if !w.Have.LinkRate || w.LinkRateMbps != 866 {
		t.Errorf("link rate = %v, want 866", w.LinkRateMbps)
	}
	if w.SSID != "CorpWiFi" || w.BSSID != "a1:b2:c3:d4:e5:f6" {
		t.Errorf("ssid/bssid = %q/%q", w.SSID, w.BSSID)
	}
	if w.Channel != 36 || w.Band != "5GHz" {
		t.Errorf("channel/band = %d/%q, want 36/5GHz", w.Channel, w.Band)
	}
}

func TestParseNetshWlan(t *testing.T) {
	out := `
    Name                   : Wi-Fi
    State                  : connected
    SSID                   : GuestNet
    BSSID                  : 00:11:22:33:44:55
    Radio type             : 802.11ax
    Band                   : 5 GHz
    Channel                : 44
    Receive rate (Mbps)    : 1200.1
    Transmit rate (Mbps)   : 1200.1
    Signal                 : 82%`
	w := parseNetshWlan(out)
	if !w.Associated || w.SSID != "GuestNet" || w.BSSID != "00:11:22:33:44:55" {
		t.Fatalf("assoc/ssid/bssid wrong: %+v", w)
	}
	if w.Band != "5GHz" || w.Channel != 44 {
		t.Errorf("band/channel = %q/%d", w.Band, w.Channel)
	}
	if !w.Have.Signal || w.SignalPct != 82 {
		t.Errorf("signal = %v%%, want 82", w.SignalPct)
	}
	if !w.Have.RSSI || w.RSSIDBm != -59 { // 82/2-100 = -59
		t.Errorf("derived RSSI = %v, want -59", w.RSSIDBm)
	}
	if !w.Have.LinkRate || w.LinkRateMbps != 1200.1 {
		t.Errorf("link rate = %v, want 1200.1", w.LinkRateMbps)
	}
}

func TestParseNmcli(t *testing.T) {
	// nmcli -t escapes ':' inside the BSSID with a backslash.
	out := `no:Neighbor1:AA\:AA\:AA\:AA\:AA\:AA:1:2412 MHz:130 Mbit/s:42
yes:MyHome:BB\:BB\:BB\:BB\:BB\:BB:36:5180 MHz:540 Mbit/s:77
no:Neighbor2:CC\:CC\:CC\:CC\:CC\:CC:11:2462 MHz:144 Mbit/s:55`
	w := parseNmcli(out)
	if !w.Associated || w.SSID != "MyHome" {
		t.Fatalf("active row wrong: %+v", w)
	}
	if w.BSSID != "BB:BB:BB:BB:BB:BB" {
		t.Errorf("BSSID unescape = %q", w.BSSID)
	}
	if w.Channel != 36 || w.Band != "5GHz" {
		t.Errorf("channel/band = %d/%q", w.Channel, w.Band)
	}
	if !w.Have.LinkRate || w.LinkRateMbps != 540 {
		t.Errorf("rate = %v, want 540", w.LinkRateMbps)
	}
	if !w.Have.Signal || w.SignalPct != 77 {
		t.Errorf("signal = %v, want 77", w.SignalPct)
	}
}

func TestParseProcNetWireless(t *testing.T) {
	out := `Inter-| sta-|   Quality        |   Discarded packets               | Missed | WE
 face | tus | link level noise |  nwid  crypt   frag  retry   misc | beacon | 22
  wlan0: 0000   58.  -45.  -256        0      0      0      0      0        0`
	w := parseProcNetWireless(out)
	if !w.Present || !w.Associated {
		t.Fatalf("should be present+associated: %+v", w)
	}
	if !w.Have.RSSI || w.RSSIDBm != -45 {
		t.Errorf("RSSI = %v, want -45", w.RSSIDBm)
	}
	if w.Have.Noise { // -256 is the "invalid" sentinel and must be dropped
		t.Errorf("noise -256 should be treated as unavailable")
	}
}

func TestBandHelpers(t *testing.T) {
	if bandFromChannel(6) != "2.4GHz" || bandFromChannel(36) != "5GHz" || bandFromChannel(200) != "6GHz" {
		t.Errorf("bandFromChannel wrong")
	}
	if bandFromMHz(2412) != "2.4GHz" || bandFromMHz(5180) != "5GHz" || bandFromMHz(6000) != "6GHz" {
		t.Errorf("bandFromMHz wrong")
	}
}
