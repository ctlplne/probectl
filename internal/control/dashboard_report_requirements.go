// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"slices"

	gouuid "github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

var errReportSourceRequirements = errors.New("report source requirements are incomplete or inconsistent")

// This format contains requirements to check against a future reader. It has
// neither frozen result tables nor any principal, credential or durable grant.
type reportSourceRequirements struct {
	Version          int                        `json:"version"`
	TenantID         string                     `json:"tenant_id"`
	Inputs           []reportFlowInput          `json:"inputs"`
	Permissions      []string                   `json:"permissions"`
	Contexts         []reportContextRequirement `json:"contexts"`
	ContextsCaptured bool                       `json:"contexts_captured"`
}

func marshalReportSourceRequirements(ctx context.Context, capture *reportFlowCapture) (json.RawMessage, error) {
	if capture == nil {
		return nil, errReportSourceRequirements
	}
	for _, table := range capture.Tables {
		if table.TenantID != capture.TenantID {
			return nil, errReportSourceRequirements
		}
	}
	requirements := reportSourceRequirements{Version: 1, TenantID: capture.TenantID,
		Inputs: capture.Inputs, Permissions: capture.Permissions,
		Contexts: capture.Contexts, ContextsCaptured: capture.ContextsCaptured}
	if err := validateReportSourceRequirements(ctx, requirements); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(requirements)
	if err != nil || len(raw) > store.ReportArtifactSourceEnvelopeMaxBytes {
		return nil, errReportSourceRequirements
	}
	return raw, nil
}

func parseReportSourceRequirements(ctx context.Context, raw json.RawMessage) (*reportFlowCapture, error) {
	if len(raw) == 0 || len(raw) > store.ReportArtifactSourceEnvelopeMaxBytes {
		return nil, errReportSourceRequirements
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var requirements reportSourceRequirements
	if err := decoder.Decode(&requirements); err != nil {
		return nil, errReportSourceRequirements
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return nil, errReportSourceRequirements
	}
	if err := validateReportSourceRequirements(ctx, requirements); err != nil {
		return nil, err
	}
	return &reportFlowCapture{TenantID: requirements.TenantID, Inputs: requirements.Inputs,
		Permissions: requirements.Permissions, Contexts: requirements.Contexts,
		ContextsCaptured: requirements.ContextsCaptured}, nil
}

func reportRequirementUUID(id string) bool {
	parsed, err := gouuid.Parse(id)
	return err == nil && parsed != gouuid.Nil && parsed.String() == id
}

func validateReportSourceRequirements(ctx context.Context, value reportSourceRequirements) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	tenant, ok := tenancy.FromContext(ctx)
	if !ok || value.Version != 1 || tenant.String() != value.TenantID || !reportRequirementUUID(value.TenantID) ||
		len(value.Inputs) == 0 || !slices.Contains(value.Permissions, permAIQuery) || !slices.Contains(value.Permissions, permFlowRead) {
		return errReportSourceRequirements
	}
	for _, permission := range value.Permissions {
		if permission != permAIQuery && !reportFlowReadPermission(permission) {
			return errReportSourceRequirements
		}
	}
	usesTags := slices.Contains(value.Permissions, permTagsRead)
	if usesTags && !value.ContextsCaptured || len(value.Contexts) > 0 && (!usesTags || !value.ContextsCaptured) {
		return errReportSourceRequirements
	}
	if !reportRequirementStringsFit(ctx, value) {
		return errReportSourceRequirements
	}
	if err := validateReportSourceInputs(ctx, value.Inputs, usesTags); err != nil {
		return err
	}
	for _, requirement := range value.Contexts {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := validateStoredReportContext(value.TenantID, requirement); err != nil {
			return err
		}
	}
	return ctx.Err()
}

// Raw scalar bytes are a lower bound on the final JSON. Refuse impossible
// inputs before encoding; validated UUIDs and fixed field sets also bound
// structural overhead. The encoded-size check remains authoritative.
func reportRequirementStringsFit(ctx context.Context, value reportSourceRequirements) bool {
	remaining := store.ReportArtifactSourceEnvelopeMaxBytes
	charge := func(value string) bool {
		if len(value) > remaining {
			return false
		}
		remaining -= len(value)
		return true
	}
	for _, permission := range value.Permissions {
		if !charge(permission) {
			return false
		}
	}
	for _, input := range value.Inputs {
		if ctx.Err() != nil {
			return false
		}
		for _, value := range []string{input.ID, input.Version, input.Period, input.TagRevision} {
			if !charge(value) {
				return false
			}
		}
	}
	for _, requirement := range value.Contexts {
		if ctx.Err() != nil || len(requirement.Resource) != 6 || !charge(requirement.ContextID) {
			return false
		}
		for key, value := range requirement.Resource {
			if !charge(key) || !charge(value) {
				return false
			}
		}
		for _, permission := range requirement.Permissions {
			if !charge(permission) {
				return false
			}
		}
	}
	return true
}

func validateReportSourceInputs(ctx context.Context, inputs []reportFlowInput, usesTags bool) error {
	versions := make(map[string]string)
	periods := make(map[string]bool)
	for _, input := range inputs {
		if err := ctx.Err(); err != nil {
			return err
		}
		key := input.ID + ":" + input.Period
		if !reportRequirementUUID(input.ID) || input.Period != "current" && input.Period != "previous" ||
			input.From.IsZero() || !input.From.Before(input.To) || periods[key] {
			return errReportSourceRequirements
		}
		if _, err := flow.QueryViewVersion(input.Version); err != nil {
			return errReportSourceRequirements
		}
		if prior := versions[input.ID]; prior != "" && prior != input.Version {
			return errReportSourceRequirements
		}
		if usesTags {
			if _, err := flow.QueryViewVersion(input.TagRevision); err != nil || input.TagAsOf.IsZero() {
				return errReportSourceRequirements
			}
		}
		versions[input.ID], periods[key] = input.Version, true
	}
	for id := range versions {
		if !periods[id+":current"] {
			return errReportSourceRequirements
		}
	}
	return nil
}

func validateStoredReportContext(tenant string, requirement reportContextRequirement) error {
	if !reportRequirementUUID(requirement.ContextID) || len(requirement.Resource) != 6 ||
		requirement.Resource[auth.ResourceTenantKey] != tenant || requirement.Resource["context_id"] != requirement.ContextID ||
		!reportRequirementUUID(requirement.Resource["site_id"]) || !reportRequirementUUID(requirement.Resource["vrf_id"]) ||
		!slices.Contains(requirement.Permissions, permFlowRead) || !slices.Contains(requirement.Permissions, permTagsRead) {
		return errReportSourceRequirements
	}
	for _, label := range []string{"site_label", "vrf_label"} {
		if _, exists := requirement.Resource[label]; !exists {
			return errReportSourceRequirements
		}
	}
	for _, permission := range requirement.Permissions {
		if !reportFlowReadPermission(permission) {
			return errReportSourceRequirements
		}
	}
	return nil
}
