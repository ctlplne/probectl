// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"encoding/json"

	"github.com/ctlplne/probectl/internal/ai/mcp"
	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/incident"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type mcpIncidentCarrierBackend struct{ server *Server }

func incidentCarrierToolOption(server *Server) (mcp.Option, error) {
	var document struct {
		Components struct {
			Schemas map[string]json.RawMessage `json:"schemas"`
		} `json:"components"`
	}
	if err := json.Unmarshal(openapiJSON, &document); err != nil {
		return nil, err
	}
	schema, err := nativeMCPInputSchemas(document.Components.Schemas, map[string]any{"incident_carrier_pack": map[string]any{"$ref": "#/components/schemas/IncidentCarrierCommand"}})
	if err != nil {
		return nil, err
	}
	return mcp.WithCarrierPackBackend(mcpIncidentCarrierBackend{server}, schema["incident_carrier_pack"]), nil
}

func (b mcpIncidentCarrierBackend) CarrierPack(ctx context.Context, actor *auth.Principal, input mcp.CarrierPackCommand) (mcp.SignedCarrierResult, error) {
	none := mcp.SignedCarrierResult{}
	if b.server == nil || b.server.pool == nil || len(b.server.evidenceSigningKey) == 0 {
		return none, apierror.Unavailable("signed carrier evidence is unavailable")
	}
	if actor == nil || actor.UserID == "" || b.server.requireMFA && !actor.MFASatisfied {
		return none, apierror.Forbidden("a current tenant user and required MFA are necessary")
	}
	ctx, err := bindFlowRoleContext(ctx, actor)
	if err != nil {
		return none, err
	}
	budget := flowstore.ExplorerOperationBudget(ctx, b.server.flowStore)
	if budget.Validate() != nil {
		return none, apierror.Unavailable("carrier admission is unavailable")
	}
	ctx, cancel := context.WithTimeout(ctx, budget.ExecutionLimit)
	retained := false
	defer func() {
		if !retained {
			cancel()
		}
	}()
	ctx = context.WithValue(ctx, incidentImpactExportKey{}, true)
	check := func(ctx context.Context) error {
		if err := mcp.CheckOriginatingCredential(ctx); err != nil {
			return err
		}
		current, err := loadCurrentUserAuthority(ctx, b.server.pool, actor.TenantID, actor.UserID)
		if err != nil {
			return err
		}
		ctx, principal, err := current.requestContext(ctx, actor)
		if err != nil {
			return err
		}
		return b.server.authorizeIncidentVerdict(ctx, principal, map[string]string{auth.ResourceTenantKey: actor.TenantID, "incident_id": input.IncidentID})
	}
	if err := check(ctx); err != nil {
		return none, err
	}
	release, err := b.server.beginIncidentVerdictQuery(ctx, actor)
	if err != nil {
		return none, err
	}
	defer func() {
		if !retained {
			release()
		}
	}()
	var inc *incident.Incident
	if err := tenancy.InTenantReadSnapshot(ctx, b.server.pool, func(ctx context.Context, sc tenancy.Scope) error {
		var err error
		inc, err = (store.Incidents{}).Get(ctx, sc, input.IncidentID)
		return err
	}); err != nil {
		return none, err
	}
	raw, manifest, publication, err := b.server.prepareCarrierPackage(ctx, actor, inc, incident.CarrierInput{From: input.From, To: input.To})
	if err != nil {
		return none, err
	}
	result, err := mcp.NewSignedCarrierResult(raw, actor.TenantID, input.IncidentID)
	if err != nil {
		return none, err
	}
	if err := publication(ctx); err != nil {
		return none, err
	}
	if err := check(ctx); err != nil {
		return none, err
	}
	if err := tenancy.InTenant(ctx, b.server.pool, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := audit.TenantAppend(ctx, sc, actor.UserID, "incident.evidence_export", manifest.PackageID, map[string]any{"incident_id": inc.ID, "profile": "carrier", "transport": "mcp", "from": input.From, "to": input.To})
		return err
	}); err != nil {
		return none, err
	}
	// Retain the admitted, tenant-bound operation context. The native server
	// supplies its transport context here, which has no storage tenant binding.
	// The child still inherits transport cancellation and the exact credential
	// guard, and its finite deadline/release remain live through publication.
	final := func(_ context.Context) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := publication(ctx); err != nil {
			return err
		}
		return check(ctx)
	}
	if err := mcp.RetainNativePublication(ctx, final, func() { release(); cancel() }); err != nil {
		return none, err
	}
	retained = true
	return result, nil
}
