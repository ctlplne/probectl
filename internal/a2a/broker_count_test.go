// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package a2a

import (
	"errors"
	"testing"
)

// TestStartSessionRejectsOverLargeCount proves ING-30: the broker refuses a
// session whose probe count exceeds MaxSessionCount (the field is a uint32, so
// an unbounded count would drive a multi-GB allocation on the initiating
// agent), while a sane count still starts a session. The session/mesh API maps
// the rejection to HTTP 400.
func TestStartSessionRejectsOverLargeCount(t *testing.T) {
	b := NewBroker()
	if _, err := b.StartSession("t1", "agent-A", "agent-B", "udp", MaxSessionCount+1); !errors.Is(err, ErrSessionCountTooLarge) {
		t.Fatalf("over-large count: err = %v, want ErrSessionCountTooLarge", err)
	}
	if _, err := b.StartSession("t1", "agent-A", "agent-B", "udp", 10); err != nil {
		t.Fatalf("sane count: unexpected error %v", err)
	}
}
