// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package mcp

import "encoding/json"

const jsonRPCVersion = "2.0"

// rpcRequest is a JSON-RPC 2.0 request (or notification, when ID is absent).
type rpcRequest struct {
	JSONRPC  string          `json:"jsonrpc"`
	ID       json.RawMessage `json:"id,omitempty"`
	Method   string          `json:"method"`
	Params   json.RawMessage `json:"params,omitempty"`
	protocol requestProtocol
}

// rpcResponse is a JSON-RPC 2.0 response.
type rpcResponse struct {
	JSONRPC    string          `json:"jsonrpc"`
	ID         json.RawMessage `json:"id,omitempty"`
	Result     any             `json:"result,omitempty"`
	Error      *rpcError       `json:"error,omitempty"`
	wireBudget int
	nodeBudget int
	finalize   func()
	prepared   bool
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

// Error codes: the JSON-RPC reserved range plus probectl's auth/limit codes.
const (
	codeParse          = -32700
	codeInvalidRequest = -32600
	codeMethodNotFound = -32601
	codeInvalidParams  = -32602
	codeInternal       = -32603
	codeUnauthorized   = -32001
	codeForbidden      = -32002
	codeRateLimited    = -32003
	codeUnavailable    = -32004
)

func resultResponse(id json.RawMessage, result any) *rpcResponse {
	return &rpcResponse{JSONRPC: jsonRPCVersion, ID: id, Result: result}
}

func errorResponse(id json.RawMessage, code int, msg string) *rpcResponse {
	return &rpcResponse{JSONRPC: jsonRPCVersion, ID: id, Error: &rpcError{Code: code, Message: msg}}
}

func marshalResponse(v *rpcResponse) ([]byte, error) {
	limit, nodes := maxMCPToolResultBytes, maxMCPToolResultNodes
	if v != nil {
		if v.wireBudget > 0 {
			limit = v.wireBudget
		}
		if v.nodeBudget > 0 {
			nodes = v.nodeBudget
		}
	}
	return marshalBoundedJSONNodes(v, limit, false, nodes)
}

func marshal(v *rpcResponse) []byte {
	b, _ := marshalWithCode(v)
	return b
}

// The HTTP status comes from this same bounded encoding, including its
// fallback. Do not parse a complete large result again to discover its code.
func marshalWithCode(v *rpcResponse) ([]byte, int) {
	code := 0
	if v != nil && v.Error != nil {
		code = v.Error.Code
	}
	b, err := marshalResponse(v)
	if err != nil {
		code = codeInternal
		// Never echo a caller-controlled ID or source error on the exceptional
		// path. This fixed response itself goes through the same source and
		// writer budgets.
		b, _ = marshalBoundedJSON(
			errorResponse(nil, codeInternal, "tool result exceeds response size limit"),
			maxMCPToolResultBytes,
			false,
		)
	}
	return b, code
}
