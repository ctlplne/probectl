// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package mcp

import (
	"bytes"
	"encoding/json"
	"math/big"
	"strings"
	"unicode/utf8"
)

const (
	modernProtocolVersion  = "2026-07-28"
	metaProtocolVersion    = "io.modelcontextprotocol/protocolVersion"
	metaClientCapabilities = "io.modelcontextprotocol/clientCapabilities"
	metaClientInfo         = "io.modelcontextprotocol/clientInfo"
	metaServerInfo         = "io.modelcontextprotocol/serverInfo"
	codeHeaderMismatch     = -32020
	codeUnsupportedVersion = -32022
	codeModernUnauthorized = -33001
	codeModernForbidden    = -33002
	codeModernRateLimited  = -33003
	codeModernUnavailable  = -33004
)

type requestProtocol struct {
	modern       bool
	version      string
	progress     json.RawMessage
	frameReserve int
}

// One canonical envelope is reused by HTTP validation, stream admission and
// dispatch. Metadata is untrusted protocol context, never an identity source.
func decodeRPC(raw []byte, requireModern bool) (rpcRequest, *rpcResponse) {
	var req rpcRequest
	req.protocol.modern = requireModern
	if !utf8.Valid(raw) || !json.Valid(raw) {
		return req, errorResponse(nil, codeParse, "parse error")
	}
	var root map[string]json.RawMessage
	if err := json.Unmarshal(raw, &root); err != nil || root == nil {
		return req, errorResponse(nil, codeInvalidRequest, "invalid request")
	}
	var params map[string]json.RawMessage
	_ = json.Unmarshal(root["params"], &params)
	var meta map[string]json.RawMessage
	_ = json.Unmarshal(params["_meta"], &meta)
	_, hasVersion := meta[metaProtocolVersion]
	_, hasCaps := meta[metaClientCapabilities]
	_, hasClient := meta[metaClientInfo]
	var method string
	_ = json.Unmarshal(root["method"], &method)
	intent := requireModern || hasVersion || hasCaps || hasClient || method == "server/discover"
	req.protocol.modern = intent
	if !intent {
		var requested string
		if method == "initialize" && json.Unmarshal(params["protocolVersion"], &requested) == nil && requested == legacyProtocolVersion {
			return decodeLegacy2025RPC(raw)
		}
		// Preserve historical2024 decoding only in the explicit legacy branch.
		if json.Unmarshal(raw, &req) != nil {
			return req, errorResponse(nil, codeInvalidRequest, "invalid request")
		}
	} else {
		req.ID, req.Params = root["id"], root["params"]
		if json.Unmarshal(root["jsonrpc"], &req.JSONRPC) != nil || json.Unmarshal(root["method"], &req.Method) != nil {
			return req, errorResponse(nil, codeInvalidRequest, "invalid request envelope")
		}
	}
	if len(req.ID) > maxMCPRequestIDBytes {
		return req, errorResponse(nil, codeInvalidRequest, "request id exceeds size limit")
	}
	if !intent {
		return req, nil
	}
	req.protocol.modern = true
	invalid := func(code int, message string) (rpcRequest, *rpcResponse) {
		return req, errorResponse(req.ID, code, message)
	}
	if err := boundedJSONObjectSyntax(raw, 4<<20, false); err != nil {
		return invalid(codeInvalidRequest, "invalid request envelope")
	}
	if req.JSONRPC != jsonRPCVersion || len(root["jsonrpc"]) == 0 || len(root["method"]) == 0 || req.Method == "" {
		return invalid(codeInvalidRequest, "invalid request envelope")
	}
	if _, ok := requestIDKey(req.ID); !ok {
		return req, errorResponse(nil, codeInvalidRequest, "request id must be a non-null string or integer")
	}
	if params == nil || meta == nil {
		return invalid(codeInvalidParams, "required request metadata is missing")
	}
	if json.Unmarshal(meta[metaProtocolVersion], &req.protocol.version) != nil || req.protocol.version == "" {
		return invalid(codeInvalidParams, "required protocol version is missing")
	}
	var capabilities map[string]json.RawMessage
	if json.Unmarshal(meta[metaClientCapabilities], &capabilities) != nil || capabilities == nil {
		return invalid(codeInvalidParams, "required client capabilities are missing")
	}
	if info, present := meta[metaClientInfo]; present {
		if !validImplementation(info) {
			return invalid(codeInvalidParams, "invalid client information")
		}
	}
	if req.protocol.version != modernProtocolVersion {
		err := errorResponse(req.ID, codeUnsupportedVersion, "unsupported protocol version")
		err.Error.Data = map[string]any{"supported": []string{modernProtocolVersion, legacyProtocolVersion, protocolVersion}, "requested": req.protocol.version}
		return req, err
	}
	if token, present := meta["progressToken"]; present {
		if _, ok := requestIDKey(token); !ok {
			return invalid(codeInvalidParams, "invalid progress token")
		}
		req.protocol.progress = append(json.RawMessage(nil), token...)
	}
	return req, nil
}

// Numeric IDs are compared by exact value without expanding large exponents.
// Work and allocation stay proportional to the already bounded input token.
func requestIDKey(raw json.RawMessage) (string, bool) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || len(raw) > maxMCPRequestIDBytes || !json.Valid(raw) {
		return "", false
	}
	if raw[0] == '"' {
		var value string
		if json.Unmarshal(raw, &value) != nil {
			return "", false
		}
		return "s:" + value, true
	}
	if raw[0] != '-' && (raw[0] < '0' || raw[0] > '9') {
		return "", false
	}
	number := strings.ToLower(string(raw))
	coefficient, exponent, hasExponent := strings.Cut(number, "e")
	var power big.Int
	if hasExponent {
		if _, ok := power.SetString(exponent, 10); !ok {
			return "", false
		}
	}
	negative := strings.HasPrefix(coefficient, "-")
	coefficient = strings.TrimPrefix(coefficient, "-")
	whole, fraction, _ := strings.Cut(coefficient, ".")
	digits := strings.TrimLeft(whole+fraction, "0")
	if digits == "" {
		return "n:0", true
	}
	significant := strings.TrimRight(digits, "0")
	power.Add(&power, big.NewInt(int64(len(digits)-len(significant)-len(fraction))))
	if power.Sign() < 0 {
		return "", false
	}
	sign := ""
	if negative {
		sign = "-"
	}
	return "n:" + sign + significant + "e" + power.String(), true
}

func (s *Server) prepareResponse(req rpcRequest, response *rpcResponse) *rpcResponse {
	if response == nil || (!req.protocol.modern && req.protocol.version != legacyProtocolVersion) || response.prepared {
		return response
	}
	response.prepared = true
	if response.Error != nil {
		if _, valid := requestIDKey(response.ID); !valid {
			response.ID = nil // modern error schema omits an unreadable/invalid ID
		}
		switch response.Error.Code {
		case codeUnauthorized:
			response.Error.Code = codeModernUnauthorized
		case codeForbidden:
			response.Error.Code = codeModernForbidden
		case codeRateLimited:
			response.Error.Code = codeModernRateLimited
		case codeUnavailable:
			response.Error.Code = codeModernUnavailable
		}
		return response
	}
	if !req.protocol.modern {
		return response
	}
	result := map[string]any{}
	if fields, ok := response.Result.(map[string]any); ok {
		for key, value := range fields {
			result[key] = value
		}
	}
	result["resultType"] = "complete"
	result["_meta"] = map[string]any{metaServerInfo: s.info}
	response.Result = result
	return response
}

func (s *Server) discoverResult() map[string]any {
	return map[string]any{"supportedVersions": []string{modernProtocolVersion, legacyProtocolVersion, protocolVersion}, "capabilities": map[string]any{"tools": map[string]any{}}}
}

// Keep primitive decoding helpers explicit; metadata never populates principal,
// cost policy, store selection or permissions.
func singleHeaderValue(values []string) (string, bool) {
	if len(values) != 1 {
		return "", false
	}
	return values[0], true
}

func modernHTTPStatus(code int) int {
	switch code {
	case codeParse, codeInvalidRequest, codeInvalidParams, codeHeaderMismatch, codeUnsupportedVersion:
		return 400
	case codeMethodNotFound:
		return 404
	case codeModernRateLimited:
		return 429
	default:
		return 200
	}
}

func modernVersionHeader(raw string) bool {
	return raw != "" && raw != protocolVersion && raw != "2025-11-25"
}
