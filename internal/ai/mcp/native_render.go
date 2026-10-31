// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package mcp

import "errors"

// NativeFlowRenderBudget is operator-owned allocation admission, independent
// of query reach. It is copied into a server at construction, never from a
// client's tool arguments. Legacy tools retain their smaller fixed budgets.
type NativeFlowRenderBudget struct {
	SourceBytes  int `json:"mcp_source_bytes"`
	WireBytes    int `json:"mcp_wire_bytes"`
	Nodes        int `json:"mcp_result_nodes"`
	CSVPageBytes int `json:"mcp_csv_page_bytes"`
}

// DefaultNativeFlowRenderBudget preserves the native preview's cost defaults.
func DefaultNativeFlowRenderBudget() NativeFlowRenderBudget {
	return NativeFlowRenderBudget{SourceBytes: 32 << 20, WireBytes: 128 << 20, Nodes: 4 << 20, CSVPageBytes: 2 << 20}
}

// Validate rejects unlimited and sentinel-overflow values. An operator may
// raise any cost independently; no request can disable a bound with zero.
func (b NativeFlowRenderBudget) Validate() error {
	ceiling := int(^uint(0)>>1) - 1
	for _, n := range []int{b.SourceBytes, b.WireBytes, b.Nodes, b.CSVPageBytes} {
		if n <= 0 || n > ceiling {
			return errors.New("mcp: native flow render budgets must be positive and sentinel safe")
		}
	}
	return nil
}

// WithNativeFlowRenderBudget sets immutable per-server native render costs.
// An invalid budget refuses native calls before invoking their backend.
func WithNativeFlowRenderBudget(b NativeFlowRenderBudget) Option {
	return func(s *Server) { s.nativeRenderBudget = b }
}
