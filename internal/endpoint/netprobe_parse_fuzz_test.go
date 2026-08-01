// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package endpoint

import "testing"

// FuzzParseTraceHops drives the traceroute-output parser with arbitrary text.
// The agent shells out to the host's traceroute and parses whatever comes
// back, so malformed or hostile-looking output must degrade to fewer hops —
// never a panic and never a hop count beyond what the text could describe
// (Foundation-Loop S-7f81b4c2).
func FuzzParseTraceHops(f *testing.F) {
	f.Add(" 1  10.0.0.1  1.234 ms\n 2  * * *\n 3  1.1.1.1  12.5 ms\n")
	f.Add("traceroute to 1.1.1.1 (1.1.1.1), 30 hops max\n")
	f.Add("99999999999 999.999.999.999 nan ms\n")
	f.Add("\n\n\n")
	f.Add("")

	f.Fuzz(func(t *testing.T, text string) {
		hops, _ := parseTraceHops(text)
		if len(hops) > len(text)+1 {
			t.Fatalf("%d hops parsed from %d bytes of text", len(hops), len(text))
		}
	})
}
