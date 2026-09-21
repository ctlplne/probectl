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

// TestExplicitMaxRecvMsgSize: FUZZ-005. The agent-transport gRPC server must set
// grpc.MaxRecvMsgSize EXPLICITLY (matching the OTLP receiver's 4 MiB) rather than
// relying on the implicit gRPC default, so the bound is intentional and visible.
func TestExplicitMaxRecvMsgSize(t *testing.T) {
	if maxRecvBytes != 4<<20 {
		t.Fatalf("maxRecvBytes = %d, want 4 MiB (must match the OTLP receiver cap)", maxRecvBytes)
	}
	src, err := os.ReadFile("server.go")
	if err != nil {
		t.Fatalf("read server.go: %v", err)
	}
	if !strings.Contains(string(src), "grpc.MaxRecvMsgSize(maxRecvBytes)") {
		t.Error("agent-transport server must pass grpc.MaxRecvMsgSize(maxRecvBytes) explicitly (FUZZ-005)")
	}
}
