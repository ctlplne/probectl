// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package endpoint

import "testing"

// FuzzWiFiParsers drives every platform WiFi text parser with arbitrary input.
// The text comes from an OS tool the agent shells out to on the user's
// machine — untrusted-shaped input the agent must survive, and the parsers
// slice fields out of it (Foundation-Loop S-7f81b4c2). None may panic, and a
// parsed channel/signal must stay inside its declared range.
func FuzzWiFiParsers(f *testing.F) {
	f.Add("     agrCtlRSSI: -55\n     SSID: office\n     channel: 44,80\n")
	f.Add("SSID                   : office\nSignal                 : 87%\nChannel                : 149\n")
	f.Add("Inter-| sta-|   Quality        |   Discarded packets\n wlan0: 0000   61.  -49.  -256\n")
	f.Add("GENERAL.CONNECTION:office\nIP4.ADDRESS[1]:10.0.0.5/24\n")
	f.Add("channel: 99999999999999999999,8000000\n")
	f.Add(":::::\n\n\n")
	f.Add("")

	f.Fuzz(func(t *testing.T, text string) {
		for name, parse := range map[string]func(string) WiFi{
			"airport":     parseAirportI,
			"netsh":       parseNetshWlan,
			"procnetwifi": parseProcNetWireless,
			"nmcli":       parseNmcli,
		} {
			w := parse(text)
			if w.Channel < 0 {
				t.Fatalf("%s: negative channel %d from %q", name, w.Channel, text)
			}
			if w.SignalPct < 0 || w.SignalPct > 100 {
				t.Fatalf("%s: signal %v outside 0..100 from %q", name, w.SignalPct, text)
			}
		}
	})
}
