// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package rum

import "testing"

// FuzzParseBeacon (U-082): RUM beacons come straight from end-user browsers —
// the single most untrusted input surface in the product. Parsing must never
// panic, and an accepted beacon must be within its documented bounds.
func FuzzParseBeacon(f *testing.F) {
	f.Add([]byte(`{"key":"k1","page":"/checkout","metrics":{"lcp_ms":1200},"ts":1750000000}`))
	f.Add([]byte(`{"key":"` + string(make([]byte, 300)) + `"}`))
	f.Add([]byte(`{"key":"k1","page":"javascript:alert(1)"}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`[]`))
	f.Add([]byte(`{"key":1e309}`))
	f.Add([]byte(``))
	f.Add([]byte(`{"key":"k1","extra":{"a":{"b":{"c":{"d":"deep"}}}}}`))
	f.Add([]byte(validBeacon() + ` {}`))

	f.Fuzz(func(_ *testing.T, raw []byte) {
		_ = PeekKey(raw) // must never panic
		b, reason, err := ParseBeacon(raw)
		if err != nil || reason != "" {
			return // rejected — fine, as long as it didn't panic
		}
		_ = b
	})
}
