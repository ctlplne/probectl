// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/evidence"
	"github.com/ctlplne/probectl/internal/incident"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// The carrier profile is deterministic and human-downloaded. It never invokes
// a model, creates a public link or sends telemetry to a carrier.
func (s *Server) handleCarrierEvidenceExport(w http.ResponseWriter, r *http.Request, actor *auth.Principal, input incident.CarrierInput) error {
	budget := flowstore.ExplorerOperationBudget(r.Context(), s.flowStore)
	if budget.Validate() != nil {
		return apierror.Unavailable("carrier export admission is unavailable")
	}
	ctx, cancel := context.WithTimeout(r.Context(), budget.ExecutionLimit)
	defer cancel()
	ctx = context.WithValue(ctx, incidentImpactExportKey{}, true)
	r = r.WithContext(ctx)
	if deadline, ok := ctx.Deadline(); ok {
		_ = http.NewResponseController(w).SetWriteDeadline(deadline.Add(15 * time.Second))
	}
	release, err := s.beginIncidentVerdictQuery(ctx, actor)
	if err != nil {
		return err
	}
	defer release()
	var inc *incident.Incident
	if err := s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
		var err error
		inc, err = (store.Incidents{}).Get(ctx, sc, r.PathValue("id"))
		return err
	}); err != nil {
		return err
	}
	packageJSON, manifest, publication, err := s.prepareCarrierPackage(ctx, actor, inc, input)
	if err != nil {
		return err
	}
	if err := publication(ctx); err != nil {
		return err
	}
	if err := s.revalidateIncidentExport(r, inc); err != nil {
		return err
	}
	if err := s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
		return s.recordAudit(ctx, sc, r, "incident.evidence_export", manifest.PackageID, map[string]any{"incident_id": inc.ID, "contract": evidence.ContractVersion, "profile": "carrier", "evidence_count": len(manifest.Evidence), "from": input.From, "to": input.To})
	}); err != nil {
		return err
	}
	if err := publication(ctx); err != nil {
		return err
	}
	if err := s.revalidateIncidentExport(r, inc); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/vnd.probectl.evidence+json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="probectl-incident-%s-carrier.json"`, inc.ID))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(packageJSON)
	return nil
}

func (s *Server) prepareCarrierPackage(ctx context.Context, actor *auth.Principal, inc *incident.Incident, input incident.CarrierInput) ([]byte, evidence.Manifest, incidentEvidenceFinalizer, error) {
	var publication incidentEvidenceFinalizer
	carrier, err := s.exportIncidentCarrier(ctx, actor, inc, input, &publication)
	if err != nil {
		return nil, evidence.Manifest{}, nil, err
	}
	if publication == nil {
		return nil, evidence.Manifest{}, nil, apierror.Unavailable("carrier original-source publication check is unavailable")
	}
	profile, err := s.staticReportOperation()
	if err != nil {
		return nil, evidence.Manifest{}, nil, apierror.Unavailable("carrier output admission is unavailable")
	}
	cost, err := carrierRetainedCost(carrier)
	if err != nil {
		return nil, evidence.Manifest{}, nil, err
	}
	if cost > profile.budget.MemoryBytes {
		return nil, evidence.Manifest{}, nil, apierror.TooLarge("complete carrier evidence exceeds configured report memory; increase the report memory allowance")
	}
	manifest, attachments, err := evidence.Build(evidence.BuildInput{TenantID: actor.TenantID, Incident: redactIncidentForShare(*inc, incidentEvidenceTenantPolicy(s.incidentEvidenceRedaction(ctx), actor.TenantID), actor.TenantID), CreatedAt: time.Now().UTC(), Carrier: carrier})
	if err != nil {
		return nil, evidence.Manifest{}, nil, apierror.Internal("carrier evidence manifest failed").Wrap(err)
	}
	packageJSON, err := evidence.Sign(manifest, attachments, s.evidenceSigningKey)
	if err != nil {
		return nil, evidence.Manifest{}, nil, apierror.Internal("carrier evidence signing failed").Wrap(err)
	}
	if int64(len(packageJSON)) > profile.output.Bytes {
		return nil, evidence.Manifest{}, nil, apierror.TooLarge("complete carrier evidence exceeds configured report output bytes; increase the report output allowance")
	}
	return packageJSON, manifest, publication, nil
}
