// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/ctlplne/probectl/internal/ai/mcp"
	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/topology"
)

func topologyFailureToolOption(s *Server) (mcp.Option, error) {
	var doc struct {
		Paths map[string]struct {
			Post struct {
				RequestBody struct {
					Content map[string]struct {
						Schema json.RawMessage `json:"schema"`
					} `json:"content"`
				} `json:"requestBody"`
			} `json:"post"`
		} `json:"paths"`
	}
	if err := json.Unmarshal(openapiJSON, &doc); err != nil {
		return nil, err
	}
	contract := doc.Paths["/v1/topology/whatif"].Post.RequestBody.Content["application/json"].Schema
	var schema struct {
		Type                 string                     `json:"type"`
		Properties           map[string]json.RawMessage `json:"properties"`
		Required             []string                   `json:"required"`
		AdditionalProperties bool                       `json:"additionalProperties"`
	}
	if err := json.Unmarshal(contract, &schema); err != nil {
		return nil, err
	}
	schema.Required = append(schema.Required, "context_id", "traffic_from", "traffic_to", "maximum_poll_gap")
	for _, field := range schema.Required {
		if !json.Valid(schema.Properties[field]) {
			return nil, apierror.Internal("topology traffic parameter contract is unavailable")
		}
	}
	input, err := json.Marshal(schema)
	if err != nil {
		return nil, err
	}
	return mcp.WithTopologyFailureBackend(s.nativeTopologyFailure, input), nil
}

func (s *Server) nativeTopologyFailure(ctx context.Context, actor *auth.Principal, input topology.FailureSimulationRequest) (json.RawMessage, error) {
	if err := mcp.CheckOriginatingCredential(ctx); err != nil {
		return nil, err
	}
	r, err := http.NewRequestWithContext(auth.WithPrincipal(ctx, actor), http.MethodPost, "/v1/topology/whatif", nil)
	if err != nil {
		return nil, err
	}
	op, err := s.beginCapacityForecast(r)
	if err != nil {
		return nil, topologyFailureError(err)
	}
	retained := false
	defer func() {
		if !retained {
			op.done()
		}
	}()
	result, err := s.measureTopologyWhatIf(op, whatIfRequest(input))
	if err != nil {
		return nil, err
	}
	body, err := marshalNativeTopologyFailure(result)
	if err != nil {
		return nil, apierror.Unavailable("complete traffic simulation output is unavailable")
	}
	if int64(len(body)) >= op.budget.ResponseBytes || int64(len(body)) >= op.budget.MemoryBytes/16 {
		return nil, apierror.TooLarge("complete traffic simulation exceeds response admission")
	}
	if err := mcp.RetainNativePublication(ctx, func(context.Context) error {
		if err := result.Traffic.checkPublication(); err != nil {
			return topologyFailureError(err)
		}
		return nil
	}, op.done); err != nil {
		return nil, err
	}
	retained = true
	return body, op.request.Context().Err()
}
