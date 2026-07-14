// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package main

import (
	"os"
	"strings"
	"testing"
)

// RED-007 (verify-first, verdict: enforcement EXISTS): the mcp-stdio entry
// authenticates PROBECTL_MCP_TOKEN BEFORE building any server or touching any
// store — exactly the contract internal/ai/mcp/stdio.go documents ("the
// binary authenticates the token before calling this"). This test pins the
// ordering: with no token, runMCPStdio must refuse immediately; a nil DB
// proves nothing else ran first (a deref would panic, failing the test).
func TestMCPAuthRequiredBeforeServing(t *testing.T) {
	old, had := os.LookupEnv("PROBECTL_MCP_TOKEN")
	_ = os.Unsetenv("PROBECTL_MCP_TOKEN")
	t.Cleanup(func() {
		if had {
			_ = os.Setenv("PROBECTL_MCP_TOKEN", old)
		}
	})

	err := runMCPStdio(nil, nil, nil) // nil cfg/log/db: nothing may be touched pre-auth
	if err == nil {
		t.Fatal("mcp-stdio without a token must refuse to serve (RED-007)")
	}
	if !strings.Contains(err.Error(), "PROBECTL_MCP_TOKEN") {
		t.Fatalf("refusal must name the missing token, got: %v", err)
	}
}
