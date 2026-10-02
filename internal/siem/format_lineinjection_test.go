// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package siem

import (
	"bytes"
	"testing"
	"time"
)

// forgedLinePresent reports whether marker appears on any line OTHER than the
// first - i.e. whether a tenant-controlled field managed to split the record
// into a second, forged line in the shared SIEM stream (AUD-15).
func forgedLinePresent(out []byte, marker string) bool {
	lines := bytes.Split(out, []byte("\n"))
	for i, ln := range lines {
		if i == 0 {
			continue // the legitimate record; an inline marker here is harmless
		}
		if bytes.Contains(ln, []byte(marker)) {
			return true
		}
	}
	return false
}

// lineInjectionEvent stuffs CR and LF (plus a forged-record payload carrying
// marker) into EVERY tenant-controlled string field, so the assertions below
// exercise every interpolation site, including the nested Attributes key/value.
func lineInjectionEvent(marker string) Event {
	// A raw CR/LF followed by what looks like a fresh record. Pre-fix this
	// splits the line; post-fix it must be neutralized to printable escapes.
	inj := "\r\n" + marker
	return Event{
		Time:     time.Date(2026, 6, 2, 12, 0, 0, 0, time.UTC),
		TenantID: "tenant-a" + inj,
		Category: Category("threat" + inj),
		Action:   "ioc.botnet_c2" + inj,
		Severity: SeverityCritical,
		Actor:    "attacker" + inj,
		Target:   "203.0.113.7" + inj,
		Outcome:  "success" + inj,
		Message:  "legitimate tenant-a event" + inj,
		Attributes: map[string]string{
			"ioc\r\nsource":         "feodo" + inj,
			"confidence" + "\r\n99": "90" + inj,
		},
	}
}

// TestFormattersRenderExactlyOneLine is the AUD-15 acceptance: for EVERY
// formatter, an Event whose fields contain \r or \n must render as exactly one
// line (no embedded CR/LF).
func TestFormattersRenderExactlyOneLine(t *testing.T) {
	const marker = "FORGED_BY_TENANT_B_a9f3"
	for _, name := range []string{"syslog", "cef", "ecs", "otlp"} {
		fmtr, ok := NewFormatter(name)
		if !ok {
			t.Fatalf("formatter %q should be known", name)
		}
		out := fmtr.Format(lineInjectionEvent(marker))
		if n := bytes.Count(out, []byte("\n")); n != 0 {
			t.Fatalf("%s formatter emitted %d embedded LF (record split across lines):\n%q", name, n, out)
		}
		if bytes.ContainsRune(out, '\r') {
			t.Fatalf("%s formatter emitted an embedded CR (record split across lines):\n%q", name, out)
		}
	}
}

// TestSyslogAndCEFNeutralizeForgedLineInjection is the targeted line-injection
// proof: for cef and syslog a planted forged record must NOT appear as its own
// line (forged_line_present == false).
func TestSyslogAndCEFNeutralizeForgedLineInjection(t *testing.T) {
	const marker = "FORGED_BY_TENANT_B_a9f3"
	for _, name := range []string{"cef", "syslog"} {
		fmtr, _ := NewFormatter(name)
		out := fmtr.Format(lineInjectionEvent(marker))
		if forgedLinePresent(out, marker) {
			t.Fatalf("%s: forged_line_present=true - tenant field forged a second record:\n%q", name, out)
		}
		// Belt-and-suspenders: a single-line record carries exactly the marker
		// text inline, never as a new physical line.
		if bytes.Count(out, []byte("\n")) != 0 {
			t.Fatalf("%s: record is not a single line:\n%q", name, out)
		}
	}
}
