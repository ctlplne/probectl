// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package mcp

import (
	"context"
	"encoding/json"
	"strconv"
	"time"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/flow"
)

type CapacityAgreementCommand struct {
	ID         string                            `json:"id,omitempty"`
	After      string                            `json:"after,omitempty"`
	Limit      *int                              `json:"limit,omitempty"`
	Version    string                            `json:"version,omitempty"`
	At         string                            `json:"at,omitempty"`
	Definition *flow.CapacityAgreementDefinition `json:"definition,omitempty"`
	Forecast   *flow.CapacityForecastRequest     `json:"forecast,omitempty"`
	Check      *flow.CapacityBillRequest         `json:"check,omitempty"`
}

type CapacityAgreementBackend interface {
	CapacityAgreements(context.Context, *auth.Principal, string, CapacityAgreementCommand) (json.RawMessage, error)
}

var capacityAgreementTools = []struct {
	name, description string
	write             bool
}{
	{"capacity_forecast", "Forecast a complete current interface or tagged circuit from original counters, with explicit training, horizon, threshold and physical bounds. No financial permission or terms are required. Missing coverage withholds trained runout; intervals are empirical residual envelopes.", false},
	{"capacity_agreements_list", "Page current tenant financial agreements; complete pages have resource admission and no total catalog ceiling.", false},
	{"capacity_agreement_bill_check", "Check complete-month measured p95, commit, overage and exact invoice difference against recorded terms and all current members. Explicit physical bounds and original counter receipts are required; incomplete coverage withholds amounts.", false},
	{"capacity_agreement_get", "Read current, exact recorded or effective agreement terms. Version and effective instant are mutually exclusive.", false},
	{"capacity_agreement_revisions", "Page complete immutable agreement revisions in recording order, including retired inventory references.", false},
	{"capacity_agreement_create", "Record complete operator financial terms for one current-tenant interface or tagged circuit.", true},
	{"capacity_agreement_update", "Append complete immutable terms only if the observed head revision still matches.", true},
	{"capacity_agreement_delete", "Delete an agreement and its recorded history only at the observed exact head revision.", true},
}

func capacityAgreementVersion(value string) bool {
	version, err := strconv.ParseInt(value, 10, 64)
	return err == nil && version > 0 && strconv.FormatInt(version, 10) == value
}

func decodeCapacityAgreementCommand(raw json.RawMessage, name string, limit int) (CapacityAgreementCommand, error) {
	var input CapacityAgreementCommand
	if err := decodeBoundedNativeArgs(raw, &input, limit); err != nil {
		return CapacityAgreementCommand{}, err
	}
	none := CapacityAgreementCommand{}
	if name == "capacity_forecast" {
		if err := validateCapacityForecastCommand(input); err != nil {
			return none, err
		}
		return input, nil
	}
	if input.Forecast != nil {
		return none, argErr("forecast input is accepted only by the forecast tool")
	}
	needsID := name != "capacity_agreements_list" && name != "capacity_agreement_create"
	if (needsID && !validTagWriteID(input.ID)) || (!needsID && input.ID != "") {
		return none, argErr("a canonical current-tenant agreement ID is required only for an existing agreement")
	}
	if input.Limit != nil && *input.Limit <= 0 {
		return none, argErr("page size must be positive when supplied")
	}
	if name != "capacity_agreement_bill_check" && input.Check != nil {
		return none, argErr("measured billing input is accepted only by the bill check")
	}
	if err := validateCapacityAgreementCommandFields(input, name); err != nil {
		return none, err
	}
	return input, nil
}

func validateCapacityForecastCommand(input CapacityAgreementCommand) error {
	if input.Forecast == nil || input.ID != "" || input.Check != nil || input.Definition != nil || input.After != "" || input.Limit != nil || input.Version != "" || input.At != "" {
		return argErr("forecast requires only complete forecast input, never financial or authority hints")
	}
	return nil
}

func validateCapacityAgreementCommandFields(input CapacityAgreementCommand, name string) error {
	switch name {
	case "capacity_agreement_bill_check":
		if input.Check == nil || input.Definition != nil || input.After != "" || input.Limit != nil || input.Version != "" || input.At != "" {
			return argErr("bill check requires only agreement ID and complete check input")
		}
	case "capacity_agreements_list", "capacity_agreement_revisions":
		if input.Definition != nil || input.Version != "" || input.At != "" {
			return argErr("agreement pages do not accept terms or a version/effective lookup")
		}
		if input.After != "" && ((name == "capacity_agreements_list" && !validTagWriteID(input.After)) || (name == "capacity_agreement_revisions" && !capacityAgreementVersion(input.After))) {
			return argErr("the exclusive page cursor must be an agreement ID or exact recorded revision")
		}
	case "capacity_agreement_get":
		if input.Definition != nil || input.After != "" || input.Limit != nil || input.Version != "" && input.At != "" {
			return argErr("choose current terms, exact revision or effective instant without page/mutation fields")
		}
		if input.Version != "" && !capacityAgreementVersion(input.Version) {
			return argErr("exact positive recorded revision is required")
		}
		if input.At != "" {
			if _, err := time.Parse(time.RFC3339Nano, input.At); err != nil {
				return argErr("effective instant must include an RFC3339 timezone")
			}
		}
	case "capacity_agreement_create", "capacity_agreement_update":
		if input.Definition == nil || input.After != "" || input.Limit != nil || input.At != "" || name == "capacity_agreement_create" && input.Version != "" || name == "capacity_agreement_update" && !capacityAgreementVersion(input.Version) {
			return argErr("complete terms and the observed head revision for an update are required")
		}
	case "capacity_agreement_delete":
		if !capacityAgreementVersion(input.Version) || input.Definition != nil || input.After != "" || input.Limit != nil || input.At != "" {
			return argErr("delete requires only the agreement ID and observed exact head revision")
		}
	default:
		return argErr("unknown capacity agreement command")
	}
	return nil
}

func WithCapacityAgreementBackend(backend CapacityAgreementBackend, schemas NativeFlowSchemas, inputBytes int) Option {
	return func(s *Server) {
		if backend == nil || inputBytes <= 0 {
			return
		}
		for _, item := range capacityAgreementTools {
			if !json.Valid(schemas[item.name]) {
				return
			}
		}
		s.nativeEnabled = true
		for _, item := range capacityAgreementTools {
			permission := "flow.agreements.read"
			if item.name == "capacity_forecast" {
				permission = "flow.read"
			}
			var extra []string
			if item.write {
				permission, extra = "flow.agreements.write", []string{"flow.agreements.read"}
			}
			s.tools[item.name] = Tool{Name: item.name, Permission: permission, ExtraPermissions: extra, RequiresUser: true, Native: true,
				InputSchema: append(json.RawMessage(nil), schemas[item.name]...),
				Description: item.description + " Financial terms confer no telemetry grant. Current user, credential ceiling, storage tenant and finite operation resources are checked by the shared service. Existing consent and full text/price redaction apply.",
				Invoke: func(ctx context.Context, p *auth.Principal, raw json.RawMessage) (any, error) {
					input, err := decodeCapacityAgreementCommand(raw, item.name, min(inputBytes, s.nativeRequestBytes()))
					if err != nil {
						return nil, err
					}
					return backend.CapacityAgreements(ctx, p, item.name, input)
				}}
			s.order = append(s.order, item.name)
		}
	}
}
