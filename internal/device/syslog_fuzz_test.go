// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package device

import (
	"testing"
	"time"
)

// FuzzDeviceSyslogLine drives the device-plane syslog line parser with
// arbitrary text: switches and routers emit whatever their firmware produces,
// including truncated and non-conforming lines (Foundation-Loop S-7f81b4c2).
// It must never panic, and facility/severity must stay inside the protocol's
// range whenever a PRI was recognized.
func FuzzDeviceSyslogLine(f *testing.F) {
	f.Add("<189>45: *Aug  2 10:00:00.123: %LINK-3-UPDOWN: Interface Gi0/1, changed state to down", "core-sw-1")
	f.Add("<0>", "")
	f.Add("<999999999999999999999>x", "dev")
	f.Add("no pri at all", "dev")
	f.Add("", "")

	observed := time.Unix(1_800_000_000, 0).UTC()
	f.Fuzz(func(t *testing.T, raw, fallbackDevice string) {
		ev := ParseSyslogLine(raw, fallbackDevice, observed)
		if ev.Facility < 0 || ev.Facility > 23 {
			t.Fatalf("facility %d outside 0..23 for %q", ev.Facility, raw)
		}
		if ev.Severity < 0 || ev.Severity > 7 {
			t.Fatalf("severity %d outside 0..7 for %q", ev.Severity, raw)
		}
	})
}
