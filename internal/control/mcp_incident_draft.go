// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"encoding/json"
	"time"

	"github.com/ctlplne/probectl/internal/ai"
	"github.com/ctlplne/probectl/internal/ai/mcp"
	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/incident"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func incidentDraftToolOption(server *Server) (mcp.Option, error) {
	var document struct {
		Components struct {
			Schemas map[string]json.RawMessage `json:"schemas"`
		} `json:"components"`
	}
	if err := json.Unmarshal(openapiJSON, &document); err != nil {
		return nil, err
	}
	schemas, err := nativeMCPInputSchemas(document.Components.Schemas, map[string]any{
		"incident_draft": map[string]any{"$ref": "#/components/schemas/IncidentDraftCommand"},
	})
	if err != nil {
		return nil, err
	}
	return mcp.WithIncidentDraftBackend(server.nativeIncidentDraft, schemas["incident_draft"]), nil
}

func (s *Server) nativeIncidentDraft(ctx context.Context, actor *auth.Principal, command mcp.IncidentDraftCommand, redaction ai.RedactionPolicy) (mcp.SignedIncidentDraft, error) {
	var none mcp.SignedIncidentDraft
	input := incidentDraftRequest{Kind: command.Kind, incidentEvidenceExportInput: incidentEvidenceExportInput{
		Carrier: command.Carrier, Impact: command.Impact, Verdict: command.Verdict,
	}}
	if err := input.validate(command.IncidentID, time.Now().UTC()); err != nil {
		return none, err
	}
	ctx, profile, release, err := s.beginIncidentDraft(ctx, actor)
	if err != nil {
		return none, err
	}
	ctx = context.WithValue(ctx, incidentEvidenceRedactionKey{}, redaction)
	owned := true
	defer func() {
		if owned {
			release()
		}
	}()
	revalidate := func(ctx context.Context, original *incident.Incident) error {
		if err := mcp.CheckOriginatingCredential(ctx); err != nil {
			return err
		}
		retained, err := s.readIncidentDraftSource(ctx, actor, original.ID)
		if err != nil {
			return err
		}
		return checkRetainedIncident(ctx, original, retained)
	}
	if err := mcp.CheckOriginatingCredential(ctx); err != nil {
		return none, err
	}
	prepared, err := s.prepareIncidentDraft(ctx, actor, command.IncidentID, input, profile, revalidate)
	if err != nil {
		return none, err
	}
	result, err := mcp.NewSignedIncidentDraft(prepared.result.IncidentDraft, prepared.result.Model, prepared.result.Degraded,
		prepared.result.EvidencePackage, actor.TenantID, command.IncidentID, prepared.signer)
	if err != nil {
		return none, err
	}
	check := func(_ context.Context) error {
		if err := prepared.checkEvidence(ctx); err != nil {
			return err
		}
		return revalidate(ctx, prepared.incident)
	}
	if err := check(ctx); err != nil {
		return none, err
	}
	metadata := incidentDraftAuditData(command.IncidentID, prepared.result)
	metadata["transport"] = "mcp"
	if err := tenancy.InTenant(ctx, s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := audit.TenantAppend(ctx, sc, actor.UserID, incidentDraftAuditAction, prepared.result.PackageID, metadata)
		return err
	}); err != nil {
		return none, err
	}
	if err := mcp.RetainNativePublication(ctx, check, release); err != nil {
		return none, err
	}
	owned = false
	return result, nil
}
