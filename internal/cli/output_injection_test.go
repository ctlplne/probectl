// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package cli

import (
	"bytes"
	"strings"
	"testing"
	"unicode"
)

// GAP-07: the agent/test fields the CLI prints are server-supplied and
// ultimately agent-reported (hostname, name, version, capabilities, test
// target/params). A crafted value carrying an ANSI/terminal escape sequence —
// a cursor move, a screen clear, a window-title rewrite — must never reach the
// operator's terminal raw. These tests pin that every table and detail renderer
// escapes control runes: the only control bytes left in the output are the
// structural newline/tab the renderers themselves emit, for ANY input.

// hostile packs every control-byte family an attacker can reach into one field:
// ESC (the ANSI introducer), CR/LF/TAB (row/column spoofing), NUL, BEL, DEL and
// a C1 code.
const hostile = "edge\x1b[2J\x1b[1;31mPWNED\r\n\tx\x00\x07\x7f\u0085end"

func assertNoRawControl(t *testing.T, label, out string) {
	t.Helper()
	for i, r := range out {
		if unicode.IsControl(r) && r != '\n' && r != '\t' {
			t.Fatalf("%s: raw control rune %#U at byte %d leaked to the terminal:\n%q", label, r, i, out)
		}
	}
	// Non-vacuity: the renderer must still have produced the surrounding text,
	// not swallowed the whole field.
	if !strings.Contains(out, "edge") || !strings.Contains(out, "end") {
		t.Fatalf("%s: field content was dropped rather than escaped:\n%q", label, out)
	}
}

func TestOutputRenderersEscapeControlBytes(t *testing.T) {
	agent := Agent{
		ID:             hostile,
		Name:           hostile,
		Hostname:       hostile,
		AgentVersion:   hostile,
		Status:         hostile,
		Capabilities:   []string{hostile, "dns"},
		IdentityState:  hostile,
		IdentityReason: hostile,
	}
	test := Test{
		ID:     hostile,
		Name:   hostile,
		Type:   hostile,
		Target: hostile,
		Params: map[string]string{hostile: hostile},
	}

	var buf bytes.Buffer
	printAgents(&buf, []Agent{agent})
	assertNoRawControl(t, "printAgents", buf.String())

	buf.Reset()
	printAgent(&buf, agent)
	assertNoRawControl(t, "printAgent", buf.String())

	buf.Reset()
	printTests(&buf, []Test{test})
	assertNoRawControl(t, "printTests", buf.String())

	buf.Reset()
	printTest(&buf, test)
	assertNoRawControl(t, "printTest", buf.String())
}
