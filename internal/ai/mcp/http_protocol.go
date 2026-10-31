// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package mcp

import (
	"encoding/base64"
	"encoding/json"
	"math"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"unicode/utf8"
)

func headerValues(header http.Header, name string) []string {
	var values []string
	for key, entries := range header {
		if strings.EqualFold(key, name) {
			values = append(values, entries...)
		}
	}
	return values
}

func acceptedJSONAndSSE(header http.Header) bool {
	jsonOK, sseOK := false, false
	for _, line := range headerValues(header, "Accept") {
		for _, part := range strings.Split(line, ",") {
			media, params, err := mime.ParseMediaType(strings.TrimSpace(part))
			if err != nil {
				continue
			}
			if q, present := params["q"]; present {
				value, err := strconv.ParseFloat(q, 64)
				if err != nil || math.IsNaN(value) || math.IsInf(value, 0) || value <= 0 || value > 1 {
					continue
				}
			}
			if media == "application/json" {
				jsonOK = true
			}
			if media == "text/event-stream" {
				sseOK = true
			}
		}
	}
	return jsonOK && sseOK
}

func decodedMirroredHeader(raw string) (string, bool) {
	if strings.HasPrefix(raw, "=?base64?") && strings.HasSuffix(raw, "?=") {
		value, err := base64.StdEncoding.Strict().DecodeString(strings.TrimSuffix(strings.TrimPrefix(raw, "=?base64?"), "?="))
		if err != nil || !utf8.Valid(value) {
			return "", false
		}
		return string(value), true
	}
	if raw == "" || strings.TrimSpace(raw) != raw {
		return "", false
	}
	for _, c := range raw {
		if c < 32 || c > 126 {
			return "", false
		}
	}
	return raw, true
}

func validateModernHTTP(r *http.Request, req rpcRequest) *rpcResponse {
	mismatch := func() *rpcResponse {
		return errorResponse(req.ID, codeHeaderMismatch, "request metadata headers do not match the body")
	}
	version, ok := singleHeaderValue(headerValues(r.Header, "MCP-Protocol-Version"))
	if !ok || version != req.protocol.version {
		return mismatch()
	}
	method, ok := singleHeaderValue(headerValues(r.Header, "Mcp-Method"))
	if !ok || method != req.Method {
		return mismatch()
	}
	if req.Method == "tools/call" || req.Method == "resources/read" || req.Method == "prompts/get" {
		var params map[string]json.RawMessage
		if json.Unmarshal(req.Params, &params) != nil {
			return mismatch()
		}
		field := "name"
		if req.Method == "resources/read" {
			field = "uri"
		}
		var expected string
		if json.Unmarshal(params[field], &expected) != nil || expected == "" {
			return mismatch()
		}
		name, ok := singleHeaderValue(headerValues(r.Header, "Mcp-Name"))
		if !ok {
			return mismatch()
		}
		decoded, ok := decodedMirroredHeader(name)
		if !ok || decoded != expected {
			return mismatch()
		}
	}
	return validateRequestMedia(r, req)
}

func validateLegacyHTTP(r *http.Request, req rpcRequest) *rpcResponse {
	values := headerValues(r.Header, "MCP-Protocol-Version")
	if len(values) != 0 || req.Method != "initialize" {
		version, ok := singleHeaderValue(values)
		if !ok || version != legacyProtocolVersion {
			return errorResponse(req.ID, codeInvalidRequest, "unsupported or missing legacy protocol header")
		}
	}
	return validateRequestMedia(r, req)
}

func validateRequestMedia(r *http.Request, req rpcRequest) *rpcResponse {
	if !acceptedJSONAndSSE(r.Header) {
		return errorResponse(req.ID, codeInvalidRequest, "Accept must include application/json and text/event-stream")
	}
	content, ok := singleHeaderValue(headerValues(r.Header, "Content-Type"))
	if !ok {
		return errorResponse(req.ID, codeInvalidRequest, "Content-Type must be application/json")
	}
	media, _, err := mime.ParseMediaType(content)
	if err != nil || media != "application/json" {
		return errorResponse(req.ID, codeInvalidRequest, "Content-Type must be application/json")
	}
	return nil
}
