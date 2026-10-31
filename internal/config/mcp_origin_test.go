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

func TestMCPOriginConfigurationFailsClosedAndDoesNotLogOrigins(t *testing.T) {
	cfg, err := Load(envFunc(nil))
	if err != nil || len(cfg.MCPAllowedOrigins) != 0 {
		t.Fatal("default grants browser origins")
	}
	cfg, err = Load(envFunc(map[string]string{"PROBECTL_MCP_ALLOWED_ORIGINS": "HTTPS://trusted.example:443, https://[::1]:18448"}))
	if err != nil || len(cfg.MCPAllowedOrigins) != 2 || cfg.MCPAllowedOrigins[0] != "https://trusted.example" {
		t.Fatal("configured origins not canonical", err)
	}
	if got := cfg.Redacted()["mcp_allowed_origin_count"]; got != 2 {
		t.Fatal("safe diagnostics omitted origin count")
	}
	for _, bad := range []string{"*", "null", "https://user:secret@example.test", "https://example.test/path", "https://example.test#", "file:///tmp/test"} {
		if _, err := Load(envFunc(map[string]string{"PROBECTL_MCP_ALLOWED_ORIGINS": bad})); err == nil || !strings.Contains(err.Error(), "PROBECTL_MCP_ALLOWED_ORIGINS") {
			t.Fatal("invalid trusted-origin policy did not refuse startup")
		}
	}
}
