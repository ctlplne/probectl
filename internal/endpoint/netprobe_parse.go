// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package endpoint

import (
	"net"
	"strconv"
	"strings"
)

// parseTraceHops parses the output of `traceroute -n` (Linux/macOS/BSD) AND
// `tracert -d` (Windows) into hops — the formats differ in column order but both
// are "hop-number, some RTT samples, and an IP", so one tolerant parser handles
// both. Numeric RTT samples ("12.3 ms") are averaged into the hop RTT; "*"
// samples are timeouts that drive the per-hop loss; a hop with only timeouts
// ("* * *" / "Request timed out.") yields 100% loss and an empty IP. Header and
// blank lines (whose first field is not a hop number) are ignored.
//
// reached reports whether the final hop actually responded (an IP with RTT), i.e.
// the trace got to the target rather than dying in the middle.
func parseTraceHops(text string) (hops []LastMileHop, reached bool) {
	for _, line := range strings.Split(text, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		idx, err := strconv.Atoi(fields[0])
		if err != nil {
			continue // header / banner / blank
		}
		hop := LastMileHop{Index: idx}
		var rtts []float64
		stars := 0
		for i := 1; i < len(fields); i++ {
			tok := fields[i]
			switch {
			case tok == "*":
				stars++
			case tok == "ms" || tok == "(" || tok == ")":
				// unit / decoration token — skip
			case net.ParseIP(strings.Trim(tok, "()")) != nil:
				if hop.IP == "" {
					ip := strings.Trim(tok, "()")
					hop.IP, hop.Private = ip, isPrivateIP(ip)
				}
			default:
				v := strings.TrimPrefix(tok, "<") // Windows "<1 ms"
				if f, err := strconv.ParseFloat(v, 64); err == nil && i+1 < len(fields) && fields[i+1] == "ms" {
					rtts = append(rtts, f)
				}
			}
		}
		if probes := len(rtts) + stars; probes > 0 {
			hop.LossPct = float64(stars) / float64(probes) * 100
		}
		hop.RTTMs = mean(rtts)
		hops = append(hops, hop)
	}
	if n := len(hops); n > 0 {
		last := hops[n-1]
		reached = last.IP != "" && last.RTTMs > 0
	}
	return hops, reached
}

func mean(xs []float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	sum := 0.0
	for _, x := range xs {
		sum += x
	}
	return sum / float64(len(xs))
}
