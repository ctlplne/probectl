// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package endpoint

import "fmt"

// Cause names the layer an endpoint slowdown is attributed to. The whole point
// of the endpoint agent is to answer "is it us, or the user's WiFi/ISP?", so the
// causes walk outward from the device.
type Cause string

const (
	CauseNone    Cause = "none"    // nothing impaired
	CauseWiFi    Cause = "wifi"    // the local wireless link (weak signal / noise)
	CauseLocal   Cause = "local"   // the LAN / default gateway
	CauseISP     Cause = "isp"     // the last-mile / ISP access network
	CauseNetwork Cause = "network" // beyond the last mile (the service / wider network — "not the user's WiFi or ISP")
	CauseUnknown Cause = "unknown" // a slowdown is present but no layer signal explains it
)

// LayerState is one layer's assessment.
type LayerState struct {
	Impaired bool    `json:"impaired"`
	Score    float64 `json:"score"` // 0..1 severity (how far past threshold)
	Reason   string  `json:"reason,omitempty"`
}

// Attribution is the verdict: the closest impaired layer owns the slowdown,
// because a weak near link inflates everything measured downstream of it.
type Attribution struct {
	Cause      Cause      `json:"cause"`
	Confidence float64    `json:"confidence"` // 0..1
	Summary    string     `json:"summary"`
	Slow       bool       `json:"slow"` // whether a user-visible slowdown was observed at all
	WiFi       LayerState `json:"wifi"`
	Local      LayerState `json:"local"`
	ISP        LayerState `json:"isp"`
	Network    LayerState `json:"network"`
}

// Thresholds are the (configurable) cutoffs the attribution engine uses. Defaults
// are deliberately conservative; an operator tunes them per fleet.
type Thresholds struct {
	WiFiWeakRSSIDBm   float64 `json:"wifi_weak_rssi_dbm" yaml:"wifi_weak_rssi_dbm"`     // <= this is a weak link (e.g. -75)
	WiFiPoorSignalPct float64 `json:"wifi_poor_signal_pct" yaml:"wifi_poor_signal_pct"` // <= this is weak when RSSI is absent (e.g. 35)
	GatewayHighRTTMs  float64 `json:"gateway_high_rtt_ms" yaml:"gateway_high_rtt_ms"`   // local first-hop RTT considered high (e.g. 25)
	GatewayHighLoss   float64 `json:"gateway_high_loss_pct" yaml:"gateway_high_loss_pct"`
	ISPHighRTTMs      float64 `json:"isp_high_rtt_ms" yaml:"isp_high_rtt_ms"` // ISP-edge RTT considered high (e.g. 80)
	ISPHighLoss       float64 `json:"isp_high_loss_pct" yaml:"isp_high_loss_pct"`
	SessionSlowMs     float64 `json:"session_slow_ms" yaml:"session_slow_ms"` // total session time that feels slow (e.g. 1500)
}

// DefaultThresholds returns sensible starting cutoffs.
func DefaultThresholds() Thresholds {
	return Thresholds{
		WiFiWeakRSSIDBm:   -75,
		WiFiPoorSignalPct: 35,
		GatewayHighRTTMs:  25,
		GatewayHighLoss:   2,
		ISPHighRTTMs:      80,
		ISPHighLoss:       2,
		SessionSlowMs:     1500,
	}
}

// Attribute classifies the dominant cause of a slowdown from a Sample. It is a
// pure function (no I/O) so it is exhaustively testable, and it is the engine
// behind the sprint's "attribute a slowdown to WiFi/ISP vs the network".
//
// Method: assess each layer independently, then attribute to the CLOSEST impaired
// layer (wifi → local → isp → network). Closest-first matters: a weak Wi-Fi link
// inflates the gateway, ISP, and session numbers measured through it, so blaming
// the network when the real fault is the user's Wi-Fi would be wrong — and is
// exactly the misattribution this engine must avoid.
func Attribute(s Sample, t Thresholds) Attribution {
	a := Attribution{
		WiFi:    assessWiFi(s.WiFi, t),
		Local:   assessLocal(s.Gateway, t),
		ISP:     assessISP(s.LastMile, t),
		Network: assessNetwork(s, t),
	}
	a.Slow = worstSessionMs(s.Sessions) >= t.SessionSlowMs

	switch {
	case a.WiFi.Impaired:
		a.Cause, a.Confidence = CauseWiFi, a.WiFi.Score
		a.Summary = a.WiFi.Reason
	case a.Local.Impaired:
		a.Cause, a.Confidence = CauseLocal, a.Local.Score
		a.Summary = a.Local.Reason
	case a.ISP.Impaired:
		a.Cause, a.Confidence = CauseISP, a.ISP.Score
		a.Summary = a.ISP.Reason
	case a.Slow:
		// A real slowdown with the whole local + ISP path healthy points beyond the
		// last mile — the service or wider network, i.e. NOT the user's WiFi/ISP.
		if a.Network.Impaired {
			a.Cause, a.Confidence, a.Summary = CauseNetwork, a.Network.Score, a.Network.Reason
		} else {
			a.Cause, a.Confidence, a.Summary = CauseUnknown, 0.3, "slow session with no local, ISP, or path signal to explain it"
		}
	default:
		a.Cause, a.Confidence, a.Summary = CauseNone, 1, "no impairment detected"
	}

	// A corroborating clean downstream raises confidence in a near-layer verdict;
	// an also-impaired downstream lowers it (the fault may be shared).
	a.Confidence = clamp01(a.Confidence)
	return a
}

func assessWiFi(w WiFi, t Thresholds) LayerState {
	if !w.Present || !w.Associated {
		return LayerState{} // wired or no Wi-Fi: this layer cannot be the cause
	}
	if w.Have.RSSI && w.RSSIDBm <= t.WiFiWeakRSSIDBm {
		over := (t.WiFiWeakRSSIDBm - w.RSSIDBm) / 15 // ~15 dB past threshold ≈ fully severe
		return LayerState{Impaired: true, Score: clamp01(0.5 + over), Reason: fmt.Sprintf("weak WiFi signal %.0f dBm (<= %.0f)", w.RSSIDBm, t.WiFiWeakRSSIDBm)}
	}
	if !w.Have.RSSI && w.Have.Signal && w.SignalPct <= t.WiFiPoorSignalPct {
		return LayerState{Impaired: true, Score: clamp01(0.5 + (t.WiFiPoorSignalPct-w.SignalPct)/t.WiFiPoorSignalPct), Reason: fmt.Sprintf("poor WiFi signal %.0f%% (<= %.0f%%)", w.SignalPct, t.WiFiPoorSignalPct)}
	}
	return LayerState{}
}

func assessLocal(g Gateway, t Thresholds) LayerState {
	if g.IP == "" && g.RTTMs == 0 && !g.Reachable {
		return LayerState{} // no gateway signal captured
	}
	if !g.Reachable {
		return LayerState{Impaired: true, Score: 1, Reason: "default gateway unreachable"}
	}
	if g.LossPct >= t.GatewayHighLoss {
		return LayerState{Impaired: true, Score: clamp01(g.LossPct / 20), Reason: fmt.Sprintf("local packet loss %.0f%% (>= %.0f%%)", g.LossPct, t.GatewayHighLoss)}
	}
	if g.RTTMs >= t.GatewayHighRTTMs {
		return LayerState{Impaired: true, Score: clamp01(g.RTTMs / (t.GatewayHighRTTMs * 4)), Reason: fmt.Sprintf("high local/gateway RTT %.0f ms (>= %.0f ms)", g.RTTMs, t.GatewayHighRTTMs)}
	}
	return LayerState{}
}

func assessISP(lm LastMile, t Thresholds) LayerState {
	if lm.ISPRTTMs == 0 && lm.ISPLossPct == 0 {
		return LayerState{} // no ISP-edge signal
	}
	if lm.ISPLossPct >= t.ISPHighLoss {
		return LayerState{Impaired: true, Score: clamp01(lm.ISPLossPct / 20), Reason: fmt.Sprintf("ISP-edge packet loss %.0f%% (>= %.0f%%)", lm.ISPLossPct, t.ISPHighLoss)}
	}
	if lm.ISPRTTMs >= t.ISPHighRTTMs {
		return LayerState{Impaired: true, Score: clamp01(lm.ISPRTTMs / (t.ISPHighRTTMs * 3)), Reason: fmt.Sprintf("high ISP-edge RTT %.0f ms (>= %.0f ms)", lm.ISPRTTMs, t.ISPHighRTTMs)}
	}
	return LayerState{}
}

// assessNetwork marks the wider network impaired when a session is slow AND we
// actually measured the near path (so we can say the fault is beyond it). A slow
// session with NO path visibility is left for the Unknown branch — we can't claim
// "it's the network" without having looked at the user's own path.
func assessNetwork(s Sample, t Thresholds) LayerState {
	worst := worstSessionMs(s.Sessions)
	if worst < t.SessionSlowMs || !pathMeasured(s) {
		return LayerState{}
	}
	return LayerState{Impaired: true, Score: clamp01(worst / (t.SessionSlowMs * 3)), Reason: fmt.Sprintf("slow session %.0f ms (>= %.0f ms) with a healthy local path", worst, t.SessionSlowMs)}
}

// pathMeasured reports whether we captured any near-path signal (a gateway or any
// trace hop) for this sample.
func pathMeasured(s Sample) bool {
	return s.Gateway.IP != "" || s.Gateway.RTTMs > 0 || len(s.LastMile.Hops) > 0
}

func worstSessionMs(ss []Session) float64 {
	worst := 0.0
	for _, s := range ss {
		if s.TotalMs > worst {
			worst = s.TotalMs
		}
	}
	return worst
}

func clamp01(f float64) float64 {
	if f < 0 {
		return 0
	}
	if f > 1 {
		return 1
	}
	return f
}
