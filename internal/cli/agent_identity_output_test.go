// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package cli

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

// DPR-176: an agent keeps working on the identity it holds and then stops for
// good. An operator reading the fleet from a terminal has to see the credential
// lifetime beside the status, or the only visible symptom is silence.
func TestPrintAgentsStatesTheIdentityLifetime(t *testing.T) {
	expires := time.Date(2026, 9, 19, 8, 21, 10, 0, time.UTC)
	var buf bytes.Buffer
	printAgents(&buf, []Agent{
		{ID: "11111111-1111-4111-8111-111111111111", Name: "edge-1", Status: "online",
			IdentityState: "current", IdentityExpiresAt: &expires},
		{ID: "22222222-2222-4222-8222-222222222222", Name: "browser-1", Status: "offline",
			IdentityState: "expired"},
		{ID: "33333333-3333-4333-8333-333333333333", Name: "legacy-1", Status: "online",
			IdentityState: "unknown"},
	})
	out := buf.String()
	if !strings.Contains(out, "IDENTITY") {
		t.Fatalf("the agent table has no identity column:\n%s", out)
	}
	for _, want := range []string{"valid until 2026-09-19T08:21:10Z", "EXPIRED", "unknown"} {
		if !strings.Contains(out, want) {
			t.Fatalf("the table does not state %q:\n%s", want, out)
		}
	}
}

func TestPrintAgentSaysWhyAnIdentityIsRefused(t *testing.T) {
	var buf bytes.Buffer
	printAgent(&buf, Agent{
		ID: "22222222-2222-4222-8222-222222222222", Name: "browser-1", Status: "offline",
		IdentityState:  "expired",
		IdentityReason: "Agent identity expired 2026-09-18T08:21:10Z. An expired SVID cannot rotate itself; the agent must enroll again.",
	})
	out := buf.String()
	if !strings.Contains(out, "identity:      EXPIRED") {
		t.Fatalf("agent detail does not state the identity state:\n%s", out)
	}
	if !strings.Contains(out, "cannot rotate itself") {
		t.Fatalf("agent detail does not carry the reason:\n%s", out)
	}
	// An agent with no recorded identity says so rather than looking healthy.
	buf.Reset()
	printAgent(&buf, Agent{ID: "1", Name: "legacy", Status: "online"})
	if !strings.Contains(buf.String(), "identity:      -") {
		t.Fatalf("an agent with no identity record must print a dash:\n%s", buf.String())
	}
}
