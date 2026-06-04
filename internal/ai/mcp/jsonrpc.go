package mcp

import "encoding/json"

const jsonRPCVersion = "2.0"

// rpcRequest is a JSON-RPC 2.0 request (or notification, when ID is absent).
type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// rpcResponse is a JSON-RPC 2.0 response.
type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
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
)

func resultResponse(id json.RawMessage, result any) *rpcResponse {
	return &rpcResponse{JSONRPC: jsonRPCVersion, ID: id, Result: result}
}

func errorResponse(id json.RawMessage, code int, msg string) *rpcResponse {
	return &rpcResponse{JSONRPC: jsonRPCVersion, ID: id, Error: &rpcError{Code: code, Message: msg}}
}

func marshal(v *rpcResponse) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		b, _ = json.Marshal(errorResponse(nil, codeInternal, "marshal error"))
	}
	return b
}
