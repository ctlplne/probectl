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

// TestParseSyslogLineParsesRFC5424 pins RTP-09: ParseSyslogLine must recognize
// the RFC 5424 VERSION field and extract the hostname, app-name and the real
// MSG (with the structured-data block stripped). Before the fix the VERSION
// token defeated both header branches, leaving hostname/app-name empty and the
// whole post-PRI remainder in the message.
func TestParseSyslogLineParsesRFC5424(t *testing.T) {
	observed := time.Date(2026, 6, 30, 13, 0, 1, 0, time.UTC)
	line := `<34>1 2026-06-30T13:00:00Z edge-1 firewall 731 link_down ` +
		`[probectlSrc@32473 ifIndex="7" role="wan"] uplink down on Gi0/1`
	ev := ParseSyslogLine(line, "", observed)

	if ev.Facility != 4 || ev.Severity != 2 || ev.SeverityText != "critical" {
		t.Fatalf("priority normalization: facility=%d severity=%d text=%q", ev.Facility, ev.Severity, ev.SeverityText)
	}
	if ev.Version != 1 {
		t.Fatalf("rfc5424 version = %d, want 1", ev.Version)
	}
	if ev.Hostname != "edge-1" {
		t.Fatalf("rfc5424 hostname = %q, want edge-1", ev.Hostname)
	}
	if ev.AppName != "firewall" {
		t.Fatalf("rfc5424 app-name = %q, want firewall", ev.AppName)
	}
	if ev.Device != "edge-1" {
		t.Fatalf("rfc5424 device fallback = %q, want edge-1 (hostname)", ev.Device)
	}
	if ev.Message != "uplink down on Gi0/1" {
		t.Fatalf("rfc5424 message = %q, want the MSG with structured data stripped", ev.Message)
	}

	// A NILVALUE ("-") timestamp falls back to the observed time, and an absent
	// MSG yields an empty message without tripping the parser.
	nilTS := ParseSyslogLine(`<13>1 - host-2 app-2 - - - `, "", observed)
	if nilTS.Version != 1 || nilTS.Hostname != "host-2" || nilTS.AppName != "app-2" {
		t.Fatalf("rfc5424 nil-value header = %+v", nilTS)
	}
	if !nilTS.ObservedAt.Equal(observed) {
		t.Fatalf("rfc5424 nil timestamp observed_at = %v, want %v", nilTS.ObservedAt, observed)
	}
}
