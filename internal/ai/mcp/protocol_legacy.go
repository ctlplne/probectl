// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package mcp

import (
	"encoding/json"
	"unicode/utf8"
)

const legacyProtocolVersion = "2025-11-25"

// The negotiated legacy revision comes only from the transport's explicit
// initialize context. Metadata never supplies tenant, grants or store scope.
func decodeLegacy2025RPC(raw []byte) (rpcRequest, *rpcResponse) {
	req := rpcRequest{protocol: requestProtocol{version: legacyProtocolVersion}}
	if !utf8.Valid(raw) || !json.Valid(raw) {
		return req, errorResponse(nil, codeParse, "parse error")
	}
	var root map[string]json.RawMessage
	if json.Unmarshal(raw, &root) != nil || root == nil {
		return req, errorResponse(nil, codeInvalidRequest, "invalid request")
	}
	req.ID, req.Params = root["id"], root["params"]
	invalid := func(code int, message string) (rpcRequest, *rpcResponse) {
		return req, errorResponse(req.ID, code, message)
	}
	if boundedJSONObjectSyntax(raw, 4<<20, false) != nil || json.Unmarshal(root["jsonrpc"], &req.JSONRPC) != nil || req.JSONRPC != jsonRPCVersion || json.Unmarshal(root["method"], &req.Method) != nil || req.Method == "" {
		return invalid(codeInvalidRequest, "invalid request envelope")
	}
	if _, valid := requestIDKey(req.ID); !valid {
		return req, errorResponse(nil, codeInvalidRequest, "request id must be a non-null string or integer")
	}
	var params map[string]json.RawMessage
	if len(req.Params) > 0 && (json.Unmarshal(req.Params, &params) != nil || params == nil) {
		return invalid(codeInvalidParams, "invalid params")
	}
	if req.Method == "initialize" {
		var requested *string
		var capabilities map[string]json.RawMessage
		if json.Unmarshal(params["protocolVersion"], &requested) != nil || requested == nil || *requested == "" || json.Unmarshal(params["capabilities"], &capabilities) != nil || capabilities == nil || !validImplementation(params["clientInfo"]) {
			return invalid(codeInvalidParams, "initialize requires protocolVersion, capabilities and clientInfo")
		}
	}
	if rawMeta, present := params["_meta"]; present {
		var meta map[string]json.RawMessage
		if json.Unmarshal(rawMeta, &meta) != nil || meta == nil {
			return invalid(codeInvalidParams, "invalid request metadata")
		}
		if token, present := meta["progressToken"]; present {
			if _, valid := requestIDKey(token); !valid {
				return invalid(codeInvalidParams, "invalid progress token")
			}
			req.protocol.progress = append(json.RawMessage(nil), token...)
		}
	}
	return req, nil
}

func validImplementation(raw json.RawMessage) bool {
	var fields map[string]json.RawMessage
	var name, version *string
	return json.Unmarshal(raw, &fields) == nil && fields != nil && json.Unmarshal(fields["name"], &name) == nil && json.Unmarshal(fields["version"], &version) == nil && name != nil && version != nil
}
