// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package mcp

import (
	"bytes"
	"context"
	"encoding/json"

	"github.com/ctlplne/probectl/internal/alert"
	"github.com/ctlplne/probectl/internal/auth"
)

type AlertEvaluationsInput struct {
	RuleID      string `json:"rule_id"`
	Fingerprint string `json:"fingerprint,omitempty"`
	Limit       *int   `json:"limit,omitempty"`
}

type AlertEvaluationBackend interface {
	AlertTagAdmission(context.Context, *auth.Principal) (func(), error)
	AlertEvaluations(context.Context, *auth.Principal, AlertEvaluationsInput) (alert.EvaluationsResult, error)
}

// Native evaluation receipts share the API's tenant-first domain read. Source
// clocks can be withheld independently without hiding ordinary alert receipts.
func WithAlertEvaluationBackend(backend AlertEvaluationBackend, schema json.RawMessage) Option {
	return func(s *Server) {
		if backend == nil || len(schema) == 0 {
			return
		}
		tool := Tool{Name: "alert_evaluations", Permission: "alert.read", RequiresUser: true, Native: true, Query: true,
			Description: "Read bounded owned alert evaluation transitions. The actual metadata selection clock is returned only under current user and credential source grants; configuration binding clocks are not execution proof.",
			Admit:       backend.AlertTagAdmission, InputSchema: append(json.RawMessage(nil), schema...),
			Invoke: func(ctx context.Context, p *auth.Principal, raw json.RawMessage) (any, error) {
				var input AlertEvaluationsInput
				if err := decodeBoundedNativeArgs(raw, &input, 16*1024); err != nil || !validAlertTagRuleID(input.RuleID) || len(input.Fingerprint) > 2048 || (input.Limit != nil && (*input.Limit < 1 || *input.Limit > 100)) {
					return nil, argErr("an owned rule, bounded fingerprint and limit between 1 and 100 are required")
				}
				var fields map[string]json.RawMessage
				if err := json.Unmarshal(raw, &fields); err != nil {
					return nil, argErr("receipt arguments must be an object")
				}
				for _, value := range fields {
					if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
						return nil, argErr("receipt arguments cannot be null")
					}
				}
				result, err := backend.AlertEvaluations(ctx, p, input)
				if err != nil {
					return nil, err
				}
				return projectNativeAlertEvaluations(result), nil
			},
		}
		s.tools[tool.Name] = tool
		s.order = append(s.order, tool.Name)
	}
}

// Preserve typed server identities in the already-authorized flow evidence.
// Free text, including citation text and any stored strings, still traverses
// normal native response redaction.
func projectNativeAlertEvaluations(result alert.EvaluationsResult) any {
	items := make([]any, 0, len(result.Items))
	hasFlow := false
	for _, item := range result.Items {
		evidence := item.Expectation.Seasonal
		if evidence == nil || evidence.Exact == nil {
			items = append(items, item)
			continue
		}
		hasFlow = true
		items = append(items, nativeFlowEvaluationReceipt{
			EvaluationReceipt: item,
			RuleID:            NativeRoleUUID(item.RuleID),
			Expectation: nativeFlowEvaluationExpectation{EvaluationExpectation: item.Expectation,
				Seasonal: nativeFlowSeasonalEvidence{SeasonalEvaluationEvidence: *evidence,
					Subject: NativeRoleDigest(evidence.Subject), IncidentID: NativeRoleUUID(evidence.IncidentID)}},
		})
	}
	if !hasFlow {
		return result
	}
	return struct {
		alert.EvaluationsResult
		Items []any `json:"items"`
	}{result, items}
}

type nativeFlowEvaluationReceipt struct {
	alert.EvaluationReceipt
	RuleID      NativeRoleUUID                  `json:"rule_id"`
	Expectation nativeFlowEvaluationExpectation `json:"expectation"`
}

type nativeFlowEvaluationExpectation struct {
	alert.EvaluationExpectation
	Seasonal nativeFlowSeasonalEvidence `json:"seasonal"`
}

type nativeFlowSeasonalEvidence struct {
	alert.SeasonalEvaluationEvidence
	Subject    NativeRoleDigest `json:"subject"`
	IncidentID NativeRoleUUID   `json:"incident_id,omitempty"`
}
