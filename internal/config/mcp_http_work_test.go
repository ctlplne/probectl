// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package config

import (
	"testing"
	"time"
)

func TestMCPHTTPWorkCostConfiguration(t *testing.T) {
	cfg, err := Load(envFunc(nil))
	if err != nil || cfg.MCPHTTPWorkTimeout != time.Minute || cfg.MCPHTTPActiveRequests != 1024 {
		t.Fatal("HTTP work defaults absent", err)
	}
	cfg, err = Load(envFunc(map[string]string{"PROBECTL_MCP_HTTP_WORK_TIMEOUT": "2m", "PROBECTL_MCP_HTTP_ACTIVE_REQUESTS": "2048"}))
	if err != nil || cfg.MCPHTTPWorkTimeout != 2*time.Minute || cfg.MCPHTTPActiveRequests != 2048 {
		t.Fatal("configured HTTP work costs ignored", err)
	}
	if costs, ok := cfg.Redacted()["mcp_http_work_cost"].(map[string]any); !ok || costs["timeout"] != "2m0s" || costs["active_requests"] != 2048 {
		t.Fatal("HTTP work cost diagnostics absent")
	}
	for key, values := range map[string][]string{"PROBECTL_MCP_HTTP_WORK_TIMEOUT": {"0", "-1s", "25h"}, "PROBECTL_MCP_HTTP_ACTIVE_REQUESTS": {"0", "-1", "1000001"}} {
		for _, bad := range values {
			if _, err := Load(envFunc(map[string]string{key: bad})); err == nil {
				t.Fatal("invalid HTTP work cost accepted", key, bad)
			}
		}
	}
}
