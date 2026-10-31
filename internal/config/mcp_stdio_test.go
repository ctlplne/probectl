// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package config

import (
	"strings"
	"testing"
)

func TestMCPStdioCostConfiguration(t *testing.T) {
	cfg, err := Load(envFunc(nil))
	if err != nil || cfg.MCPStdioWorkers != 2 || cfg.MCPStdioQueued != 8 {
		t.Fatal("stdio defaults missing", err)
	}
	cfg, err = Load(envFunc(map[string]string{"PROBECTL_MCP_STDIO_WORKERS": "3", "PROBECTL_MCP_STDIO_QUEUED": "12"}))
	if err != nil || cfg.MCPStdioWorkers != 3 || cfg.MCPStdioQueued != 12 {
		t.Fatal("operator stdio costs ignored", err)
	}
	if costs, ok := cfg.Redacted()["mcp_stdio_cost"].(map[string]any); !ok || costs["workers"] != 3 || costs["queued"] != 12 {
		t.Fatal("stdio costs absent from safe diagnostics")
	}
	for _, key := range []string{"PROBECTL_MCP_STDIO_WORKERS", "PROBECTL_MCP_STDIO_QUEUED"} {
		for _, bad := range []string{"0", "-1", "10001", "unlimited"} {
			if _, err := Load(envFunc(map[string]string{key: bad})); err == nil || !strings.Contains(err.Error(), key) {
				t.Fatal("invalid stdio cost did not refuse startup")
			}
		}
	}
}
