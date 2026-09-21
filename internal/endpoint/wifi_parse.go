// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package endpoint

import (
	"strconv"
	"strings"
)

// This file holds the PORTABLE Wi-Fi output parsers. The OS-specific collectors
// (wifi_{linux,darwin,windows}.go) only shell out to the platform tool and hand
// its text here, so the parsing — the part with real logic — is unit-tested with
// fixtures on every platform, including the default CI build.

// parseAirportI parses macOS `airport -I` (the system Wi-Fi report). Missing
// fields stay unset with their Have flag false (graceful degradation).
func parseAirportI(text string) WiFi {
	w := WiFi{Present: true}
	for _, line := range strings.Split(text, "\n") {
		key, val, ok := splitColon(line)
		if !ok {
			continue
		}
		switch key {
		case "agrCtlRSSI":
			if f, err := strconv.ParseFloat(val, 64); err == nil {
				w.RSSIDBm, w.Have.RSSI, w.Associated = f, true, true
			}
		case "agrCtlNoise":
			if f, err := strconv.ParseFloat(val, 64); err == nil && f > -256 {
				w.NoiseDBm, w.Have.Noise = f, true
			}
		case "lastTxRate":
			if f, err := strconv.ParseFloat(val, 64); err == nil {
				w.LinkRateMbps, w.Have.LinkRate = f, true
			}
		case "SSID":
			w.SSID = val
		case "BSSID":
			w.BSSID = val
		case "channel":
			w.Channel, w.Band = parseAirportChannel(val)
		case "state":
			if val == "running" {
				w.Associated = true
			}
		}
	}
	return w
}

// parseChannel reads a WiFi channel number from a single untrusted OS-tool
// field. The text is whatever an OS command printed, so a malformed or
// negative value (e.g. "-1") must not survive as a negative channel — there
// is no such thing. Anything unparseable or below 1 collapses to 0, the
// "unknown channel" sentinel every downstream (bandFromChannel, readback)
// already treats as unset.
func parseChannel(v string) int {
	ch, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil || ch < 0 {
		return 0
	}
	return ch
}

// parseAirportChannel handles airport's "36,80" (channel,width) form.
func parseAirportChannel(v string) (int, string) {
	num := v
	if i := strings.IndexAny(v, ","); i >= 0 {
		num = v[:i]
	}
	ch := parseChannel(num)
	return ch, bandFromChannel(ch)
}

// parseNetshWlan parses Windows `netsh wlan show interfaces`.
func parseNetshWlan(text string) WiFi {
	w := WiFi{Present: true}
	for _, line := range strings.Split(text, "\n") {
		key, val, ok := splitColon(line)
		if !ok {
			continue
		}
		switch key {
		case "State":
			w.Associated = strings.EqualFold(val, "connected")
		case "SSID": // avoid matching "BSSID"
			w.SSID = val
		case "BSSID":
			w.BSSID = val
		case "Band":
			w.Band = normalizeBand(val)
		case "Channel":
			w.Channel = parseChannel(val)
			if w.Band == "" {
				w.Band = bandFromChannel(w.Channel)
			}
		case "Signal":
			if pct, err := strconv.ParseFloat(strings.TrimSuffix(val, "%"), 64); err == nil {
				pct = clampPct(pct) // untrusted tool text: a percentage stays within 0..100
				w.SignalPct, w.Have.Signal = pct, true
				w.RSSIDBm, w.Have.RSSI = signalPctToRSSI(pct), true // netsh gives %, derive an approximate dBm
			}
		case "Receive rate (Mbps)", "Transmit rate (Mbps)":
			if w.LinkRateMbps == 0 {
				if f, err := strconv.ParseFloat(val, 64); err == nil {
					w.LinkRateMbps, w.Have.LinkRate = f, true
				}
			}
		}
	}
	return w
}

// parseProcNetWireless parses Linux /proc/net/wireless (the first associated
// interface). Columns: link  level  noise — level is the signal in dBm.
func parseProcNetWireless(text string) WiFi {
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		i := strings.Index(line, ":")
		if i <= 0 || strings.HasPrefix(line, "Inter") || strings.HasPrefix(line, "face") {
			continue
		}
		// Columns after the interface name: status, link-quality, level, noise.
		fields := strings.Fields(line[i+1:])
		if len(fields) < 4 {
			continue
		}
		w := WiFi{Present: true, Associated: true}
		if q, err := strconv.ParseFloat(strings.TrimSuffix(fields[1], "."), 64); err == nil {
			w.SignalPct, w.Have.Signal = clampPct(q/70*100), true // link quality is /70 on most drivers
		}
		if lvl, err := strconv.ParseFloat(strings.TrimSuffix(fields[2], "."), 64); err == nil {
			w.RSSIDBm, w.Have.RSSI = lvl, true
		}
		if n, err := strconv.ParseFloat(strings.TrimSuffix(fields[3], "."), 64); err == nil && n > -256 {
			w.NoiseDBm, w.Have.Noise = n, true
		}
		return w
	}
	return WiFi{Present: true}
}

// parseNmcli parses Linux `nmcli -t -f ACTIVE,SSID,BSSID,CHAN,FREQ,RATE,SIGNAL dev wifi`,
// taking the active row. nmcli is terse-escaped: ':' inside a field is "\:".
func parseNmcli(text string) WiFi {
	for _, line := range strings.Split(text, "\n") {
		if line == "" {
			continue
		}
		f := splitNmcli(line)
		if len(f) < 7 || !strings.EqualFold(f[0], "yes") {
			continue
		}
		w := WiFi{Present: true, Associated: true, SSID: f[1], BSSID: f[2]}
		w.Channel = parseChannel(f[3])
		if mhz := firstInt(f[4]); mhz > 0 {
			w.Band = bandFromMHz(mhz)
		} else {
			w.Band = bandFromChannel(w.Channel)
		}
		if r := firstFloat(f[5]); r > 0 {
			w.LinkRateMbps, w.Have.LinkRate = r, true
		}
		if sig, err := strconv.ParseFloat(f[6], 64); err == nil {
			sig = clampPct(sig) // untrusted tool text: a percentage stays within 0..100
			w.SignalPct, w.Have.Signal = sig, true
			w.RSSIDBm, w.Have.RSSI = signalPctToRSSI(sig), true
		}
		return w
	}
	return WiFi{Present: true}
}

// --- small shared helpers ---

// splitColon splits "  key : value " on the FIRST colon, trimming both sides.
func splitColon(line string) (key, val string, ok bool) {
	i := strings.Index(line, ":")
	if i < 0 {
		return "", "", false
	}
	key = strings.TrimSpace(line[:i])
	val = strings.TrimSpace(line[i+1:])
	if key == "" {
		return "", "", false
	}
	return key, val, true
}

// splitNmcli splits a terse nmcli row on unescaped colons, unescaping "\:".
func splitNmcli(line string) []string {
	var out []string
	var cur strings.Builder
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case c == '\\' && i+1 < len(line):
			cur.WriteByte(line[i+1])
			i++
		case c == ':':
			out = append(out, cur.String())
			cur.Reset()
		default:
			cur.WriteByte(c)
		}
	}
	out = append(out, cur.String())
	return out
}

func bandFromChannel(ch int) string {
	switch {
	case ch >= 1 && ch <= 14:
		return "2.4GHz"
	case ch >= 32 && ch <= 177:
		return "5GHz"
	case ch > 177:
		return "6GHz"
	default:
		return ""
	}
}

func bandFromMHz(mhz int) string {
	switch {
	case mhz >= 2400 && mhz < 2500:
		return "2.4GHz"
	case mhz >= 5000 && mhz < 5925:
		return "5GHz"
	case mhz >= 5925 && mhz <= 7125:
		return "6GHz"
	default:
		return ""
	}
}

func normalizeBand(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	switch {
	case strings.HasPrefix(v, "2.4"):
		return "2.4GHz"
	case strings.HasPrefix(v, "5"):
		return "5GHz"
	case strings.HasPrefix(v, "6"):
		return "6GHz"
	default:
		return ""
	}
}

// signalPctToRSSI approximates dBm from a 0..100 signal percentage (Microsoft's
// own mapping: 0% ≈ -100 dBm, 100% ≈ -50 dBm). Used only when the OS reports a
// percentage rather than a real dBm, so attribution has a single RSSI scale.
func signalPctToRSSI(pct float64) float64 {
	return pct/2 - 100
}

func clampPct(p float64) float64 {
	if p < 0 {
		return 0
	}
	if p > 100 {
		return 100
	}
	return p
}

func firstInt(s string) int {
	return int(firstFloat(s))
}

func firstFloat(s string) float64 {
	f := strings.Fields(strings.TrimSpace(s))
	if len(f) == 0 {
		return 0
	}
	v, _ := strconv.ParseFloat(f[0], 64)
	return v
}
