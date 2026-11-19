// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package mcp

import (
	"github.com/ctlplne/probectl/internal/alert"
	"github.com/ctlplne/probectl/internal/flow"
)

// NativeFlowFieldComparison declares the fields sent through native MCP.
type NativeFlowFieldComparison struct {
	ViewID  string                       `json:"view_id"`
	Version string                       `json:"version"`
	Mode    string                       `json:"mode"`
	Measure string                       `json:"measure"`
	Cadence string                       `json:"cadence"`
	TopKeys int                          `json:"top_keys"`
	Before  flow.FieldComparisonSlice    `json:"before"`
	After   flow.FieldComparisonSlice    `json:"after"`
	Changes []NativeFlowFieldChange      `json:"changes"`
	History *flow.FieldComparisonHistory `json:"history,omitempty"`
}

type NativeFlowFieldChange struct {
	Kind   string                      `json:"kind"`
	Key    string                      `json:"key"`
	Group  []NativeFlowDimension       `json:"group"`
	Before *NativeFlowFieldObservation `json:"before,omitempty"`
	After  *NativeFlowFieldObservation `json:"after,omitempty"`
	Delta  string                      `json:"delta,omitempty"`
}

type NativeFlowFieldObservation struct {
	Rank      int               `json:"rank"`
	Value     string            `json:"value"`
	Secondary []NativeFlowValue `json:"secondary,omitempty"`
	Share     string            `json:"share,omitempty"`
	Citation  string            `json:"citation"`
}

type NativeAlertFieldReceipt struct {
	Comparison NativeFlowFieldComparison `json:"comparison"`
	Signals    []alert.FieldSignalLink   `json:"signals"`
}
