// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

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
