// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"strings"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/flow"
)

type PeeringEstimateBackend interface {
	PeeringEstimate(context.Context, *auth.Principal, flow.PeeringEstimateInput) (json.RawMessage, error)
}

// NativePeeringCounter is only for validated server-computed decimal metrics.
// Like current role UUID/revision metadata, its JSON value is unchanged; digit
// escaping keeps a mathematical counter from being mistaken for text PII.
// Arbitrary source/version/evidence strings still traverse full redaction.
type NativePeeringCounter string

func (value NativePeeringCounter) MarshalJSON() ([]byte, error) {
	if value == "" || len(value) > 1 && value[0] == '0' || len(value) > (int(^uint(0)>>1)-2)/6 {
		return nil, errors.New("invalid computed peering counter")
	}
	var out strings.Builder
	out.Grow(len(value)*6 + 2)
	out.WriteByte('"')
	for _, digit := range string(value) {
		if digit < '0' || digit > '9' {
			return nil, errors.New("invalid computed peering counter")
		}
		out.WriteString(`\u003`)
		out.WriteRune(digit)
	}
	out.WriteByte('"')
	return []byte(out.String()), nil
}

func WithPeeringEstimateBackend(backend PeeringEstimateBackend, schemas NativeFlowSchemas, admit NativeFlowAdmission) Option {
	return func(s *Server) {
		schema := schemas["flow_peering_estimate"]
		if backend == nil || admit == nil || !json.Valid(schema) {
			return
		}
		tool := Tool{Name: "flow_peering_estimate", Description: "Preview hypothetical peering over an owned IX interface and original observed routing inputs. Exact combined p95 retains unknown volumes and observed gaps; no live-session, routing-policy or guaranteed-savings claim.", InputSchema: append(json.RawMessage(nil), schema...), Permission: "flow.read", ExtraPermissions: []string{"ai.query", "entities.read", "metrics.read", "events.read"}, Native: true, RequiresUser: true, Query: true, Admit: admit, Invoke: func(ctx context.Context, p *auth.Principal, raw json.RawMessage) (any, error) {
			input, err := decodePeeringEstimateInput(raw, min(s.nativeRequestBytes(), flow.MaxPlanGrammarBytes))
			if err != nil {
				return nil, err
			}
			return backend.PeeringEstimate(ctx, p, input)
		}}
		s.nativeEnabled = true
		s.tools[tool.Name] = tool
		s.order = append(s.order, tool.Name)
	}
}

func decodePeeringEstimateInput(raw json.RawMessage, limit int) (flow.PeeringEstimateInput, error) {
	var input flow.PeeringEstimateInput
	if err := decodeBoundedNativeArgs(raw, &input, limit); err != nil {
		return flow.PeeringEstimateInput{}, err
	}
	if !validTagWriteID(input.ContextID) || !validTagWriteID(input.InterfaceID) || input.PeerASN == 0 || (input.Direction != "inbound" && input.Direction != "outbound") {
		return flow.PeeringEstimateInput{}, argErr("owned context/interface, nonzero peer ASN and inbound/outbound direction are required")
	}
	for _, value := range []string{input.IXID, input.LANID} {
		id, err := strconv.ParseInt(value, 10, 64)
		if err != nil || id <= 0 || strconv.FormatInt(id, 10) != value {
			return flow.PeeringEstimateInput{}, argErr("exact positive decimal IX/LAN identities are required")
		}
	}
	return input, nil
}
