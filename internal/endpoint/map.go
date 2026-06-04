package endpoint

import (
	"fmt"

	"github.com/imfeelingtheagi/probectl/internal/canary"
)

// Canary result types emitted by the endpoint agent. They share the "endpoint."
// prefix so the pipeline/TSDB can route them as one DEM plane while keeping the
// signals distinct.
const (
	TypeAttribution = "endpoint.attribution"
	TypeWiFi        = "endpoint.wifi"
	TypeGateway     = "endpoint.gateway"
	TypeLastMile    = "endpoint.lastmile"
	TypeSession     = "endpoint.session"
)

// ToResults maps a Sample onto the canonical canary.Result envelope (one Result
// per DEM signal) so endpoint data flows through the exact same pipeline → TSDB /
// incident path as every other canary: numeric fields become Metrics (TSDB
// series), identifiers/labels become Attributes (OTel attributes, no cardinality
// blow-up). The headline is the attribution Result.
//
// Privacy is already applied to the Sample before this point, so dropped
// identifiers are simply absent here.
func (s Sample) ToResults() []canary.Result {
	out := make([]canary.Result, 0, 4+len(s.Sessions))
	ts := s.Timestamp

	// Attribution — the headline DEM signal ("is it WiFi/ISP or the network?").
	a := s.Attribution
	out = append(out, canary.Result{
		Type:      TypeAttribution,
		Target:    s.LastMile.Target,
		Success:   a.Cause == CauseNone, // success == nothing impaired
		StartedAt: ts,
		Metrics: map[string]float64{
			"confidence":    a.Confidence,
			"slow":          b2f(a.Slow),
			"wifi_score":    a.WiFi.Score,
			"local_score":   a.Local.Score,
			"isp_score":     a.ISP.Score,
			"network_score": a.Network.Score,
		},
		Attributes: dropEmpty(map[string]string{
			"endpoint.cause":   string(a.Cause),
			"endpoint.summary": a.Summary,
		}),
	})

	// WiFi link.
	if s.WiFi.Present {
		m := map[string]float64{"associated": b2f(s.WiFi.Associated)}
		if s.WiFi.Have.RSSI {
			m["rssi_dbm"] = s.WiFi.RSSIDBm
		}
		if s.WiFi.Have.Signal {
			m["signal_pct"] = s.WiFi.SignalPct
		}
		if s.WiFi.Have.LinkRate {
			m["link_rate_mbps"] = s.WiFi.LinkRateMbps
		}
		if s.WiFi.Have.Noise {
			m["noise_dbm"] = s.WiFi.NoiseDBm
		}
		if s.WiFi.Have.Cellular {
			m["rsrp_dbm"], m["rsrq_db"], m["sinr_db"] = s.WiFi.RSRPDBm, s.WiFi.RSRQDb, s.WiFi.SINRDb
		}
		if s.WiFi.Channel > 0 {
			m["channel"] = float64(s.WiFi.Channel)
		}
		out = append(out, canary.Result{
			Type: TypeWiFi, Target: s.WiFi.SSID, Success: s.WiFi.Associated, StartedAt: ts,
			Metrics: m,
			Attributes: dropEmpty(map[string]string{
				"wifi.ssid": s.WiFi.SSID, "wifi.bssid": s.WiFi.BSSID, "wifi.band": s.WiFi.Band,
			}),
		})
	}

	// Gateway / local network.
	if s.Gateway.IP != "" || s.Gateway.RTTMs > 0 || s.Gateway.Reachable {
		out = append(out, canary.Result{
			Type: TypeGateway, Target: s.Gateway.IP, Success: s.Gateway.Reachable, StartedAt: ts,
			Metrics:    map[string]float64{"rtt_ms": s.Gateway.RTTMs, "loss_pct": s.Gateway.LossPct, "reachable": b2f(s.Gateway.Reachable)},
			Attributes: dropEmpty(map[string]string{"gateway.ip": s.Gateway.IP}),
		})
	}

	// Last-mile path segments.
	if len(s.LastMile.Hops) > 0 {
		out = append(out, canary.Result{
			Type: TypeLastMile, Target: s.LastMile.Target, Success: s.LastMile.Reached, StartedAt: ts,
			Metrics: map[string]float64{
				"local_rtt_ms": s.LastMile.LocalRTTMs, "isp_rtt_ms": s.LastMile.ISPRTTMs,
				"isp_loss_pct": s.LastMile.ISPLossPct, "beyond_rtt_ms": s.LastMile.BeyondRTTMs,
				"hops": float64(len(s.LastMile.Hops)),
			},
			Attributes: map[string]string{"lastmile.reached": fmt.Sprintf("%t", s.LastMile.Reached)},
		})
	}

	// Per-target browser sessions.
	for _, sess := range s.Sessions {
		out = append(out, canary.Result{
			Type: TypeSession, Target: sess.Target, Success: sess.Success, Error: sess.Error, StartedAt: ts,
			Metrics: map[string]float64{
				"dns_ms": sess.DNSms, "connect_ms": sess.ConnectMs, "tls_ms": sess.TLSms,
				"ttfb_ms": sess.TTFBms, "total_ms": sess.TotalMs, "status": float64(sess.Status),
			},
		})
	}
	return out
}

func b2f(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

func dropEmpty(m map[string]string) map[string]string {
	for k, v := range m {
		if v == "" {
			delete(m, k)
		}
	}
	if len(m) == 0 {
		return nil
	}
	return m
}
