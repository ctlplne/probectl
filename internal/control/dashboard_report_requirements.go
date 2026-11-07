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
	"github.com/ctlplne/probectl/internal/store/flowstore"
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
	ContextSources   bool                       `json:"context_sources,omitempty"`
}

func marshalReportSourceRequirements(ctx context.Context, capture *reportFlowCapture, memoryLimits ...int64) (json.RawMessage, error) {
	memory, ok := reportRequirementsMemory(memoryLimits)
	if !ok || capture == nil {
		return nil, errReportSourceRequirements
	}
	for _, table := range capture.Tables {
		if table.TenantID != capture.TenantID {
			return nil, errReportSourceRequirements
		}
	}
	requirements := reportSourceRequirements{Version: 1, TenantID: capture.TenantID,
		Inputs: capture.Inputs, Permissions: capture.Permissions,
		Contexts: capture.Contexts, ContextsCaptured: capture.ContextsCaptured, ContextSources: capture.ContextSources}
	if requirements.ContextSources {
		requirements.Version = 2
	}
	if err := validateReportSourceRequirements(ctx, requirements, memory); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(requirements)
	if err != nil {
		return nil, errReportSourceRequirements
	}
	if err := admitFlowSnapshotValidity(ctx, raw, store.ReportArtifactSourceEnvelopeMaxBytes, memory); err != nil {
		return nil, err
	}
	return raw, nil
}

func parseReportSourceRequirements(ctx context.Context, raw json.RawMessage, memoryLimits ...int64) (*reportFlowCapture, error) {
	memory, ok := reportRequirementsMemory(memoryLimits)
	if !ok || len(raw) == 0 {
		return nil, errReportSourceRequirements
	}
	if err := admitFlowSnapshotValidity(ctx, raw, store.ReportArtifactSourceEnvelopeMaxBytes, memory); err != nil {
		return nil, err
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
	if err := validateReportSourceRequirements(ctx, requirements, memory); err != nil {
		return nil, err
	}
	return &reportFlowCapture{TenantID: requirements.TenantID, Inputs: requirements.Inputs,
		Permissions: requirements.Permissions, Contexts: requirements.Contexts,
		ContextsCaptured: requirements.ContextsCaptured, ContextSources: requirements.ContextSources}, nil
}

func reportRequirementUUID(id string) bool {
	parsed, err := gouuid.Parse(id)
	return err == nil && parsed != gouuid.Nil && parsed.String() == id
}

func validateReportSourceRequirements(ctx context.Context, value reportSourceRequirements, memory int64) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	tenant, ok := tenancy.FromContext(ctx)
	if !ok || value.Version != 1 && value.Version != 2 || tenant.String() != value.TenantID || !reportRequirementUUID(value.TenantID) ||
		len(value.Inputs) == 0 || !slices.Contains(value.Permissions, permAIQuery) || !slices.Contains(value.Permissions, permFlowRead) {
		return errReportSourceRequirements
	}
	for _, permission := range value.Permissions {
		if permission != permAIQuery && !reportFlowReadPermission(permission) {
			return errReportSourceRequirements
		}
	}
	for _, input := range value.Inputs {
		if input.RoutingSource && (!value.ContextSources || value.Version != 2) {
			return errReportSourceRequirements
		}
	}
	usesTags := slices.Contains(value.Permissions, permTagsRead)
	if value.ContextSources != slices.Contains(value.Permissions, "entities.read") || value.ContextSources != (value.Version == 2) ||
		(usesTags || value.ContextSources) && !value.ContextsCaptured || len(value.Contexts) > 0 && (!value.ContextsCaptured || !usesTags && !value.ContextSources) {
		return errReportSourceRequirements
	}
	if !reportRequirementStringsFit(ctx, value) {
		return errReportSourceRequirements
	}
	if err := validateReportSourceInputs(ctx, value.Inputs, usesTags, memory); err != nil {
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

func validateReportSourceInputs(ctx context.Context, inputs []reportFlowInput, usesTags bool, memory int64) error {
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
		if input.RoutingSource && !reportRoutingRequirementsComplete(input) || !input.RoutingSource && input.Routing != nil {
			return errReportSourceRequirements
		}
		if input.RoutingSource {
			tenant, _ := tenancy.FromContext(ctx)
			if _, err := decodeFlowRoutingValidity(ctx, tenant.String(), input.Routing, memory); err != nil {
				return err
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
		!reportContextReadPermissions(requirement.Permissions) {
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

func reportRequirementsMemory(limits []int64) (int64, bool) {
	memory := flowstore.DefaultExplorerBudget().MemoryBytes / 4
	if len(limits) > 1 {
		return 0, false
	}
	if len(limits) == 1 {
		memory = limits[0]
	}
	return memory, memory > 0
}

func reportRoutingRequirementsComplete(input reportFlowInput) bool {
	return input.Routing != nil && canonicalFlowRoutingDigest(input.Routing.Digest) && canonicalFlowRoutingDigest(input.Routing.InputDigest)
}
