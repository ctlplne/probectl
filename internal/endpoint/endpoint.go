// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package endpoint

import (
	"net"
	"time"
)

// Sample is one snapshot of an endpoint's last-mile experience plus the
// slowdown Attribution computed from it. Identity (tenant/agent) is stamped by
// the runtime, exactly like a canary Result.
type Sample struct {
	TenantID  string    `json:"tenant_id"`
	AgentID   string    `json:"agent_id"`
	Timestamp time.Time `json:"timestamp"`

	WiFi     WiFi      `json:"wifi"`
	Gateway  Gateway   `json:"gateway"`
	LastMile LastMile  `json:"last_mile"`
	Sessions []Session `json:"sessions,omitempty"`

	Attribution Attribution `json:"attribution"`
}

// WiFi is the local wireless link's health. Every numeric field is best-effort:
// whatever the OS exposes. The Have flags mark which metrics this device/OS
// actually reported, so a missing metric is distinguishable from a real zero
// (graceful degradation, not a false reading).
type WiFi struct {
	Present    bool `json:"present"`    // a Wi-Fi interface exists
	Associated bool `json:"associated"` // it is joined to an AP

	SSID    string `json:"ssid,omitempty"`  // the user's network name; gated by Privacy.CollectSSID
	BSSID   string `json:"bssid,omitempty"` // AP MAC — geolocatable PII; gated by Privacy.CollectBSSID (default off)
	Band    string `json:"band,omitempty"`  // "2.4GHz" | "5GHz" | "6GHz"
	Channel int    `json:"channel,omitempty"`

	RSSIDBm      float64 `json:"rssi_dbm,omitempty"`   // ~ -30 (excellent) .. -90 (unusable)
	SignalPct    float64 `json:"signal_pct,omitempty"` // 0..100 (Windows reports this directly)
	NoiseDBm     float64 `json:"noise_dbm,omitempty"`
	LinkRateMbps float64 `json:"link_rate_mbps,omitempty"`

	// Cellular last-mile (device on WWAN/5G rather than Wi-Fi).
	RSRPDBm float64 `json:"rsrp_dbm,omitempty"`
	RSRQDb  float64 `json:"rsrq_db,omitempty"`
	SINRDb  float64 `json:"sinr_db,omitempty"`

	Have WiFiHave `json:"have"`
}

// WiFiHave records which WiFi metrics were actually measured on this device.
type WiFiHave struct {
	RSSI     bool `json:"rssi"`
	Signal   bool `json:"signal"`
	LinkRate bool `json:"link_rate"`
	Noise    bool `json:"noise"`
	Cellular bool `json:"cellular"`
}

// Gateway is the default-gateway / local-network health. It is derived from the
// first hop of the last-mile trace (the first router is the default gateway), so
// no separate privileged ping is required.
type Gateway struct {
	IP        string  `json:"ip,omitempty"` // RFC1918/CGNAT; gated by Privacy.CollectGatewayIP
	Reachable bool    `json:"reachable"`
	RTTMs     float64 `json:"rtt_ms,omitempty"`
	LossPct   float64 `json:"loss_pct,omitempty"`
}

// LastMileHop is one hop on the path from the device toward a key target, with
// the per-hop RTT/loss that lets attribution separate the LAN, the ISP edge, and
// everything beyond.
type LastMileHop struct {
	Index   int     `json:"index"`
	IP      string  `json:"ip,omitempty"` // public hops gated by Privacy.CollectPublicHops
	Private bool    `json:"private"`      // RFC1918/CGNAT/link-local (inside the user's LAN/CPE)
	RTTMs   float64 `json:"rtt_ms,omitempty"`
	LossPct float64 `json:"loss_pct,omitempty"`
}

// LastMile is the path to one key target plus the derived per-segment RTT/loss.
type LastMile struct {
	Target  string        `json:"target"`
	Reached bool          `json:"reached"`
	Hops    []LastMileHop `json:"hops,omitempty"`

	// Derived segment metrics (set by classify):
	LocalRTTMs  float64 `json:"local_rtt_ms,omitempty"`  // last private hop (CPE/gateway)
	ISPRTTMs    float64 `json:"isp_rtt_ms,omitempty"`    // first public hop (ISP access edge)
	ISPLossPct  float64 `json:"isp_loss_pct,omitempty"`  // loss at the ISP edge hop
	BeyondRTTMs float64 `json:"beyond_rtt_ms,omitempty"` // final observed hop (toward the target)
}

// Session is a browser-session timing breakdown to one target (the DEM signal an
// end user actually feels). Mirrors the HTTP-canary / browser-waterfall shape.
type Session struct {
	Target    string  `json:"target"`
	Success   bool    `json:"success"`
	Error     string  `json:"error,omitempty"`
	Status    int     `json:"status,omitempty"`
	DNSms     float64 `json:"dns_ms,omitempty"`
	ConnectMs float64 `json:"connect_ms,omitempty"`
	TLSms     float64 `json:"tls_ms,omitempty"`
	TTFBms    float64 `json:"ttfb_ms,omitempty"`
	TotalMs   float64 `json:"total_ms,omitempty"`
}

// classify derives the per-segment RTT/loss from the hop list: the last private
// hop is the local CPE/gateway, the first public hop is the ISP access edge, and
// the final hop is "beyond" (toward the target/service). Called by the collector
// before attribution.
func (lm *LastMile) classify() {
	if len(lm.Hops) == 0 {
		return
	}
	for _, h := range lm.Hops {
		if h.RTTMs == 0 && h.LossPct == 0 && h.IP == "" {
			continue // an unresponsive hop ("* * *") — carries no segment signal
		}
		if h.Private {
			lm.LocalRTTMs = h.RTTMs // last private hop wins (closest to the ISP edge)
			continue
		}
		if lm.ISPRTTMs == 0 { // first public hop = ISP edge
			lm.ISPRTTMs = h.RTTMs
			lm.ISPLossPct = h.LossPct
		}
	}
	last := lm.Hops[len(lm.Hops)-1]
	lm.BeyondRTTMs = last.RTTMs
}

// gatewayFromLastMile derives gateway health from the first responsive private
// hop of the trace (the default gateway is the first router on the path).
func gatewayFromLastMile(lm LastMile) Gateway {
	for _, h := range lm.Hops {
		if h.Private && (h.IP != "" || h.RTTMs > 0) {
			return Gateway{IP: h.IP, Reachable: h.LossPct < 100, RTTMs: h.RTTMs, LossPct: h.LossPct}
		}
	}
	return Gateway{}
}

// isPrivateIP reports whether ip is inside the user's own LAN/CPE or the
// carrier's CGNAT range — i.e. not yet on the public ISP path. Unparseable or
// empty addresses are treated as non-private (a public/unknown hop).
func isPrivateIP(ip string) bool {
	p := net.ParseIP(ip)
	if p == nil {
		return false
	}
	if p.IsLoopback() || p.IsLinkLocalUnicast() || p.IsPrivate() {
		return true
	}
	// CGNAT 100.64.0.0/10 (RFC 6598) — the carrier's shared last-mile space.
	if v4 := p.To4(); v4 != nil {
		return v4[0] == 100 && v4[1] >= 64 && v4[1] <= 127
	}
	return false
}
