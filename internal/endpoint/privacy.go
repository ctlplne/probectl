// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package endpoint

import "fmt"

// Privacy controls what IDENTIFYING information the endpoint agent retains. The
// agent runs on an end user's personal device, so the default is to keep the
// measurements that diagnose experience (signal strength, RTT, loss, timings —
// none of which identify a person) while dropping fields that can locate or
// identify the user or their network. Minimization here is drop-on-collect: a
// gated-off field is cleared before the Sample is ever mapped, emitted, or
// logged, so it never leaves the device.
type Privacy struct {
	// CollectSSID keeps the network name. Low sensitivity (the user's own
	// network) but it can hint at location/identity, so it is configurable.
	CollectSSID bool `json:"collect_ssid" yaml:"collect_ssid"`
	// CollectBSSID keeps the AP's MAC address. This is geolocatable PII (public
	// wardriving databases map BSSID → physical location), so it defaults OFF.
	CollectBSSID bool `json:"collect_bssid" yaml:"collect_bssid"`
	// CollectGatewayIP keeps the default-gateway address (RFC1918/CGNAT — local,
	// low sensitivity).
	CollectGatewayIP bool `json:"collect_gateway_ip" yaml:"collect_gateway_ip"`
	// CollectPublicHops keeps the PUBLIC last-mile hop addresses. These reveal the
	// user's ISP and approximate geography, so they default OFF — the per-hop
	// RTT/loss (which is what attribution needs) is always kept; only the
	// identifying IP is dropped.
	CollectPublicHops bool `json:"collect_public_hops" yaml:"collect_public_hops"`
}

// DefaultPrivacy is the balanced, ship-by-default posture: keep the user's own
// network name and the local gateway, drop the geolocatable AP MAC and the
// public ISP-path addresses.
func DefaultPrivacy() Privacy {
	return Privacy{CollectSSID: true, CollectBSSID: false, CollectGatewayIP: true, CollectPublicHops: false}
}

// StrictPrivacy collects NO identifiers at all — only measurements. For
// high-governance fleets where even the SSID/gateway must not leave the device.
func StrictPrivacy() Privacy { return Privacy{} }

// Apply clears every identifier the policy does not permit. Measurements
// (signal/RTT/loss/timings) are never touched — they are not PII and they are
// what diagnoses the experience.
func (p Privacy) Apply(s *Sample) {
	if !p.CollectSSID {
		s.WiFi.SSID = ""
	}
	if !p.CollectBSSID {
		s.WiFi.BSSID = ""
	}
	if !p.CollectGatewayIP {
		s.Gateway.IP = ""
	}
	if !p.CollectPublicHops {
		for i := range s.LastMile.Hops {
			if !s.LastMile.Hops[i].Private {
				s.LastMile.Hops[i].IP = "" // keep RTT/loss; drop the identifying public address
			}
		}
	}
}

// Disclosure is a human-readable list of exactly what this policy collects, for
// the startup banner and operator documentation (transparency is a requirement
// for software that runs on user devices).
func (p Privacy) Disclosure() []string {
	d := []string{
		"WiFi/cellular signal quality (RSSI/RSRP/RSRQ/SINR/link-rate) — no identity",
		"local gateway + last-mile RTT and packet loss per segment — no identity",
		"browser-session timings (DNS/connect/TLS/TTFB/total) to the configured targets",
	}
	d = append(d, fmt.Sprintf("WiFi network name (SSID): %s", collected(p.CollectSSID)))
	d = append(d, fmt.Sprintf("access-point MAC (BSSID): %s", collected(p.CollectBSSID)))
	d = append(d, fmt.Sprintf("default-gateway address: %s", collected(p.CollectGatewayIP)))
	d = append(d, fmt.Sprintf("public last-mile hop addresses: %s", collected(p.CollectPublicHops)))
	return d
}

func collected(on bool) string {
	if on {
		return "collected"
	}
	return "NOT collected"
}
