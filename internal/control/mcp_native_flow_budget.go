// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"github.com/ctlplne/probectl/internal/ai/mcp"
	"github.com/ctlplne/probectl/internal/config"
	"github.com/ctlplne/probectl/internal/store/flowstore"
)

// Environment configuration refuses zero. Absent programmatic fixture values
// use library defaults, exactly as query/cache construction does. Both MCP
// transports and the REST registry use this single composition function.
func configuredNativeFlowRenderBudget(cfg *config.Config) mcp.NativeFlowRenderBudget {
	b := mcp.DefaultNativeFlowRenderBudget()
	if cfg != nil {
		for _, pair := range []struct {
			value  int
			target *int
		}{
			{cfg.FlowMCPSourceBytes, &b.SourceBytes}, {cfg.FlowMCPWireBytes, &b.WireBytes},
			{cfg.FlowMCPResultNodes, &b.Nodes}, {cfg.FlowMCPCSVPageBytes, &b.CSVPageBytes},
		} {
			if pair.value != 0 {
				*pair.target = pair.value
			}
		}
	}
	return b
}

func (s *Server) nativeFlowSchema() map[string]any {
	value := flowExplorerSchema(flowstore.ExplorerQueryBudget(s.flowStore))
	value["render_cost"] = s.flowRenderBudget
	return value
}
