// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package agenttransport

import (
	"os"
	"strings"
	"testing"
)

// TestExplicitMaxRecvMsgSize checks that the evidence listener applies a finite,
// explicit message admission. Complete configured ICMP populations require more
// room than the unrelated OTLP listener. The real transport test also sends an
// over-admission frame and verifies decode-layer ResourceExhausted.
func TestExplicitMaxRecvMsgSize(t *testing.T) {
	if maxRecvBytes != 16<<20 {
		t.Fatalf("maxRecvBytes = %d, want 16 MiB for complete configured ICMP evidence", maxRecvBytes)
	}
	src, err := os.ReadFile("server.go")
	if err != nil {
		t.Fatalf("read server.go: %v", err)
	}
	if !strings.Contains(string(src), "grpc.MaxRecvMsgSize(") {
		t.Error("agent-transport server must set grpc.MaxRecvMsgSize EXPLICITLY (FUZZ-005)")
	}
}
