// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package config

import (
	"strconv"
	"strings"
	"testing"
)

func TestMCPStdioCostConfiguration(t *testing.T) {
	cfg, err := Load(envFunc(nil))
	if err != nil || cfg.MCPStdioWorkers != 2 || cfg.MCPStdioQueued != 8 {
		t.Fatal("stdio defaults missing", err)
	}
	cfg, err = Load(envFunc(map[string]string{"PROBECTL_MCP_STDIO_WORKERS": "10001", "PROBECTL_MCP_STDIO_QUEUED": "20001"}))
	if err != nil || cfg.MCPStdioWorkers != 10001 || cfg.MCPStdioQueued != 20001 {
		t.Fatal("operator stdio costs ignored", err)
	}
	if costs, ok := cfg.Redacted()["mcp_stdio_cost"].(map[string]any); !ok || costs["workers"] != 10001 || costs["queued"] != 20001 {
		t.Fatal("stdio costs absent from safe diagnostics")
	}
	for _, key := range []string{"PROBECTL_MCP_STDIO_WORKERS", "PROBECTL_MCP_STDIO_QUEUED"} {
		for _, bad := range []string{"0", "-1", strconv.Itoa(int(^uint(0) >> 1)), "unlimited"} {
			if _, err := Load(envFunc(map[string]string{key: bad})); err == nil || !strings.Contains(err.Error(), key) {
				t.Fatal("invalid stdio cost did not refuse startup")
			}
		}
	}
}
