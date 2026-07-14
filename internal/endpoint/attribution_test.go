// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package endpoint

import "testing"

// healthyWiFi / etc. are small builders so each case reads as a scenario.
func wifi(rssi float64) WiFi {
	return WiFi{Present: true, Associated: true, RSSIDBm: rssi, Have: WiFiHave{RSSI: true}}
}

func sess(totalMs float64) Session {
	return Session{Target: "https://app", Success: true, TotalMs: totalMs}
}

// TestAttributeLayers is the sprint's "Done when": a slowdown is attributed to the
// closest impaired layer — crucially, weak local WiFi is blamed on WiFi, NOT the
// network, even though a weak near link inflates every downstream number.
func TestAttributeLayers(t *testing.T) {
	thr := DefaultThresholds()
	cases := []struct {
		name string
		s    Sample
		want Cause
	}{
		{
			name: "healthy → none",
			s: Sample{
				WiFi:     wifi(-50),
				Gateway:  Gateway{IP: "192.168.1.1", Reachable: true, RTTMs: 4},
				LastMile: LastMile{ISPRTTMs: 18},
				Sessions: []Session{sess(280)},
			},
			want: CauseNone,
		},
		{
			// The headline case: WiFi is weak AND everything downstream is inflated
			// by it (gateway 40ms, ISP 100ms, session 2200ms). It must attribute to
			// WiFi, not the network.
			name: "weak WiFi inflating the whole path → wifi (not network)",
			s: Sample{
				WiFi:     wifi(-82),
				Gateway:  Gateway{IP: "192.168.1.1", Reachable: true, RTTMs: 40},
				LastMile: LastMile{ISPRTTMs: 100},
				Sessions: []Session{sess(2200)},
			},
			want: CauseWiFi,
		},
		{
			name: "WiFi fine, high gateway RTT → local",
			s: Sample{
				WiFi:     wifi(-48),
				Gateway:  Gateway{IP: "192.168.1.1", Reachable: true, RTTMs: 40},
				LastMile: LastMile{ISPRTTMs: 20},
				Sessions: []Session{sess(2000)},
			},
			want: CauseLocal,
		},
		{
			name: "gateway unreachable → local",
			s: Sample{
				WiFi:    wifi(-48),
				Gateway: Gateway{IP: "192.168.1.1", Reachable: false, LossPct: 100},
			},
			want: CauseLocal,
		},
		{
			name: "local fine, high ISP-edge RTT → isp",
			s: Sample{
				WiFi:     wifi(-48),
				Gateway:  Gateway{IP: "192.168.1.1", Reachable: true, RTTMs: 6},
				LastMile: LastMile{ISPRTTMs: 130},
				Sessions: []Session{sess(2000)},
			},
			want: CauseISP,
		},
		{
			name: "whole local path healthy, session still slow → network",
			s: Sample{
				WiFi:     wifi(-48),
				Gateway:  Gateway{IP: "192.168.1.1", Reachable: true, RTTMs: 6},
				LastMile: LastMile{ISPRTTMs: 22},
				Sessions: []Session{sess(2600)},
			},
			want: CauseNetwork,
		},
		{
			name: "slow session but no path visibility → unknown",
			s: Sample{
				WiFi:     WiFi{}, // wired / no wifi
				Sessions: []Session{sess(2600)},
			},
			want: CauseUnknown,
		},
		{
			name: "weak WiFi by signal-% (no dBm) → wifi",
			s: Sample{
				WiFi:     WiFi{Present: true, Associated: true, SignalPct: 20, Have: WiFiHave{Signal: true}},
				Gateway:  Gateway{IP: "192.168.1.1", Reachable: true, RTTMs: 5},
				Sessions: []Session{sess(1800)},
			},
			want: CauseWiFi,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Attribute(tc.s, thr)
			if got.Cause != tc.want {
				t.Fatalf("cause = %q, want %q (summary: %s)", got.Cause, tc.want, got.Summary)
			}
			if tc.want != CauseNone && got.Summary == "" {
				t.Fatalf("an impaired verdict must carry a summary")
			}
			if got.Confidence < 0 || got.Confidence > 1 {
				t.Fatalf("confidence out of range: %v", got.Confidence)
			}
		})
	}
}

// TestAttributeWiredHostNeverBlamesWiFi confirms a wired device (no WiFi) never
// gets a WiFi verdict.
func TestAttributeWiredHostNeverBlamesWiFi(t *testing.T) {
	s := Sample{
		WiFi:     WiFi{Present: false},
		Gateway:  Gateway{IP: "10.0.0.1", Reachable: true, RTTMs: 50},
		Sessions: []Session{sess(2000)},
	}
	if got := Attribute(s, DefaultThresholds()); got.Cause != CauseLocal {
		t.Fatalf("cause = %q, want local (wired, high gateway RTT)", got.Cause)
	}
}

// TestAttributeISPLoss confirms loss at the ISP edge attributes to the ISP.
func TestAttributeISPLoss(t *testing.T) {
	s := Sample{
		WiFi:     wifi(-50),
		Gateway:  Gateway{IP: "192.168.0.1", Reachable: true, RTTMs: 5},
		LastMile: LastMile{ISPRTTMs: 30, ISPLossPct: 6},
		Sessions: []Session{sess(1700)},
	}
	if got := Attribute(s, DefaultThresholds()); got.Cause != CauseISP {
		t.Fatalf("cause = %q, want isp (ISP-edge loss)", got.Cause)
	}
}
