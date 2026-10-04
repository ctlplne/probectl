// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package canary

import (
	"context"
	"strings"
	"testing"
	"time"
)

// TestA2AInitiatorRefusesPrivateResponder proves ING-30: a deny-private guard
// (the A2A default) refuses a loopback/private responder endpoint before any
// dial, closing the SSRF reachability-oracle vector where a compromised peer
// aims the initiator at an internal host. Before the fix the initiator dialed
// whatever host the peer reported.
func TestA2AInitiatorRefusesPrivateResponder(t *testing.T) {
	_, err := RunA2AInitiator(context.Background(), "udp", "127.0.0.1:65000", 4,
		200*time.Millisecond, "peer", "sess-x", NewTargetGuard(false))
	if err == nil || !strings.Contains(err.Error(), "SSRF guard") {
		t.Fatalf("loopback responder: err = %v, want an SSRF-guard refusal", err)
	}
}

// TestA2AInitiatorRejectsOverLargeCount proves ING-30's agent-side cap: a probe
// count beyond the maximum is refused before any per-probe allocation, even if
// a crafted coordination task slips past the broker.
func TestA2AInitiatorRejectsOverLargeCount(t *testing.T) {
	_, err := RunA2AInitiator(context.Background(), "udp", "198.51.100.7:65000", maxA2AProbeCount+1,
		200*time.Millisecond, "peer", "sess-y", nil)
	if err == nil || !strings.Contains(err.Error(), "exceeds the maximum") {
		t.Fatalf("over-large count: err = %v, want a count-cap refusal", err)
	}
}
