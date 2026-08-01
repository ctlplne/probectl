// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package siem

import (
	"testing"
	"time"
)

// FuzzParseSyslog drives the syslog line parser — RFC 5424 and RFC 3164, PRI
// decoding and structured data — with arbitrary bytes. A syslog listener
// accepts whatever a device sends, so the parser must never panic and must
// never emit a facility/severity outside the protocol's range
// (Foundation-Loop S-7f81b4c2).
func FuzzParseSyslog(f *testing.F) {
	f.Add([]byte(`<34>1 2026-08-02T10:00:00Z host app 1 ID47 [ex@1 k="v"] message`))
	f.Add([]byte(`<13>Aug  2 10:00:00 host app[42]: classic bsd message`))
	f.Add([]byte(`<191>1 - - - - - -`))
	f.Add([]byte(`<`))
	f.Add([]byte(`<999>1 nope`))
	f.Add([]byte(`<34>1 2026-08-02T10:00:00Z host app 1 ID47 [unterminated`))
	f.Add([]byte{})

	received := time.Unix(1_800_000_000, 0).UTC()
	f.Fuzz(func(t *testing.T, line []byte) {
		parsed, err := parseSyslog(line, received)
		if err != nil {
			return
		}
		if parsed.facility < 0 || parsed.facility > 23 {
			t.Fatalf("facility %d outside 0..23 for %q", parsed.facility, line)
		}
		if parsed.severity < 0 || parsed.severity > 7 {
			t.Fatalf("severity %d outside 0..7 for %q", parsed.severity, line)
		}
	})
}
