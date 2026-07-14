// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package endpoint

import "testing"

func TestParseTracerouteUnix(t *testing.T) {
	out := `traceroute to 1.1.1.1 (1.1.1.1), 30 hops max, 60 byte packets
 1  192.168.1.1  1.234 ms  1.100 ms  1.050 ms
 2  100.64.0.1  8.5 ms  8.2 ms  8.9 ms
 3  203.0.113.1  12.0 ms * 12.4 ms
 4  * * *
 5  1.1.1.1  20.1 ms  20.0 ms  20.3 ms`
	hops, reached := parseTraceHops(out)
	if len(hops) != 5 {
		t.Fatalf("want 5 hops, got %d: %+v", len(hops), hops)
	}
	if hops[0].IP != "192.168.1.1" || !hops[0].Private {
		t.Errorf("hop1 = %+v, want private gateway", hops[0])
	}
	if hops[1].IP != "100.64.0.1" || !hops[1].Private { // CGNAT is private/local
		t.Errorf("hop2 = %+v, want CGNAT private", hops[1])
	}
	if hops[2].Private { // 203.0.113.1 is public (ISP edge)
		t.Errorf("hop3 should be public, got %+v", hops[2])
	}
	if hops[2].LossPct == 0 { // one of three probes was '*'
		t.Errorf("hop3 should record ~33%% loss, got %v", hops[2].LossPct)
	}
	if hops[3].IP != "" || hops[3].LossPct != 100 { // * * *
		t.Errorf("hop4 should be 100%% loss / no IP, got %+v", hops[3])
	}
	if !reached {
		t.Errorf("the trace reached the target on the final hop")
	}
	// hop1 averages 1.234/1.100/1.050
	if hops[0].RTTMs < 1.1 || hops[0].RTTMs > 1.2 {
		t.Errorf("hop1 RTT avg = %v, want ~1.13", hops[0].RTTMs)
	}
}

func TestParseTracertWindows(t *testing.T) {
	out := `
Tracing route to 1.1.1.1 over a maximum of 30 hops

  1     1 ms     1 ms     1 ms  192.168.0.1
  2     8 ms     9 ms     8 ms  100.64.0.1
  3     *        *        *     Request timed out.
  4    12 ms    <1 ms    12 ms  203.0.113.9
  5    20 ms    21 ms    20 ms  1.1.1.1

Trace complete.`
	hops, reached := parseTraceHops(out)
	if len(hops) != 5 {
		t.Fatalf("want 5 hops, got %d: %+v", len(hops), hops)
	}
	if hops[0].IP != "192.168.0.1" || !hops[0].Private {
		t.Errorf("hop1 = %+v", hops[0])
	}
	if hops[2].LossPct != 100 || hops[2].IP != "" { // Request timed out.
		t.Errorf("hop3 should be 100%% loss, got %+v", hops[2])
	}
	if hops[3].IP != "203.0.113.9" || hops[3].Private {
		t.Errorf("hop4 should be public ISP, got %+v", hops[3])
	}
	if !reached {
		t.Errorf("trace reached the target")
	}
}

func TestParseTraceHopsEmpty(t *testing.T) {
	hops, reached := parseTraceHops("traceroute to x\n")
	if len(hops) != 0 || reached {
		t.Errorf("no hops expected, got %d reached=%v", len(hops), reached)
	}
}
