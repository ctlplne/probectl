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
	"io"
	"net/http"
	"regexp"

	"github.com/ctlplne/probectl/internal/ai"
	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/incident"
	"github.com/ctlplne/probectl/internal/store"
)

type incidentEvidenceExportInput struct {
	Impact *incident.ImpactInput `json:"impact,omitempty"`
}

// Export already gathers RCA under ai.query. Preserve that stricter source
// permission in both current-authority snapshots of the deterministic read.
type incidentImpactExportKey struct{}

func decodeIncidentEvidenceExport(r *http.Request) (incidentEvidenceExportInput, error) {
	var input incidentEvidenceExportInput
	if r.Body == nil {
		return input, nil
	}
	data, err := io.ReadAll(io.LimitReader(r.Body, int64(flow.MaxPlanGrammarBytes)+1))
	if err != nil {
		return input, apierror.BadRequest("incident evidence export selections are unreadable")
	}
	if len(data) > flow.MaxPlanGrammarBytes {
		return input, apierror.Validation("incident evidence export selections exceed the request grammar allowance")
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return input, nil
	}
	request := r.Clone(r.Context())
	request.Body = io.NopCloser(bytes.NewReader(data))
	if err := decodeJSONLimit(request, flow.MaxPlanGrammarBytes, &input); err != nil {
		return input, err
	}
	return input, nil
}

func (s *Server) exportIncidentImpact(ctx context.Context, actor *auth.Principal, inc *incident.Incident, input incident.ImpactInput) (*incident.ImpactResponse, error) {
	if actor == nil || inc == nil || inc.TenantID != actor.TenantID {
		return nil, apierror.Forbidden("incident export requires its current tenant identity")
	}
	var snapshot *store.IncidentImpactInputs
	ctx = context.WithValue(ctx, incidentImpactExportKey{}, true)
	result, err := s.computeIncidentImpact(ctx, actor, inc.ID, input, &snapshot)
	if err != nil {
		return nil, err
	}
	if err := requireImpactIncidentHeader(actor.TenantID, inc, snapshot); err != nil {
		return nil, err
	}
	pol := redactionPolicy(s.cfg)
	redacted, err := redactIncidentImpact(result, pol, actor.TenantID)
	if err != nil {
		return nil, err
	}
	return &redacted, nil
}

func requireImpactIncidentHeader(tenant string, inc *incident.Incident, snapshot *store.IncidentImpactInputs) error {
	if inc == nil || snapshot == nil || inc.TenantID != tenant || snapshot.TenantID != tenant || snapshot.IncidentID != inc.ID || !snapshot.StartedAt.Equal(inc.StartedAt) || !snapshot.LastSeenAt.Equal(inc.LastSeenAt) {
		return apierror.Unavailable("incident changed while its evidence package was prepared; retry")
	}
	if (snapshot.ResolvedAt == nil) != (inc.ResolvedAt == nil) || snapshot.ResolvedAt != nil && !snapshot.ResolvedAt.Equal(*inc.ResolvedAt) {
		return apierror.Unavailable("incident resolution changed while its evidence package was prepared; retry")
	}
	ids := map[string]bool{}
	type identity struct{ contextID, entityID string }
	sources := map[string]identity{}
	rootSeen := false
	rootKnown := inc.IdentityLookupAttempted && inc.IdentityContextID != "" && inc.IdentityEntityID != ""
	if rootKnown == snapshot.RootUnresolved {
		return apierror.Unavailable("incident root identity changed while its evidence package was prepared; retry")
	}
	for _, member := range snapshot.Entities {
		rootSeen = rootSeen || member.IncidentRoot
		if member.IncidentRoot && (member.ContextID != inc.IdentityContextID || member.EntityID != inc.IdentityEntityID) {
			return apierror.Unavailable("incident root source changed while its evidence package was prepared; retry")
		}
		for _, id := range member.SignalIDs {
			ids[id] = true
			sources[id] = identity{member.ContextID, member.EntityID}
		}
	}
	if rootKnown && !rootSeen {
		return apierror.Unavailable("incident root is absent from its current evidence snapshot; retry")
	}
	for _, id := range snapshot.UnresolvedSignalIDs {
		ids[id] = true
	}
	if snapshot.SignalCount != inc.SignalCount {
		return apierror.Unavailable("incident membership changed while its evidence package was prepared; retry")
	}
	for _, signal := range inc.Signals {
		current, known := sources[signal.ID]
		oldKnown := signal.IdentityLookupAttempted && signal.IdentityContextID != "" && signal.IdentityEntityID != ""
		if !ids[signal.ID] || known != oldKnown || known && (current.contextID != signal.IdentityContextID || current.entityID != signal.IdentityEntityID) {
			return apierror.Unavailable("incident signal source changed while its evidence package was prepared; retry")
		}
	}
	return nil
}

func redactIncidentImpact(value incident.ImpactResponse, pol ai.RedactionPolicy, tenant string) (incident.ImpactResponse, error) {
	pol = incidentEvidenceTenantPolicy(pol, tenant)
	// A typed copy preserves mathematical counters, canonical UUIDs and
	// hashes while applying current privacy policy to human-owned labels.
	body, err := json.Marshal(value)
	if err != nil {
		return incident.ImpactResponse{}, err
	}
	var out incident.ImpactResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return out, err
	}
	for i := range out.Customers {
		customer := &out.Customers[i]
		customer.TagKey = ai.RedactTextForTenant(customer.TagKey, pol, tenant)
		customer.Value = ai.RedactTextForTenant(customer.Value, pol, tenant)
		for j := range customer.SLOIDs {
			customer.SLOIDs[j] = ai.RedactTextForTenant(customer.SLOIDs[j], pol, tenant)
		}
	}
	return out, nil
}

// The signed handoff omits the raw tenant identity even when it is embedded
// in operator-owned prose or annotations. Preserve canonical citation IDs and
// exact counter strings; apply the existing keyed redactor only to label text.
func incidentEvidenceTenantPolicy(pol ai.RedactionPolicy, tenant string) ai.RedactionPolicy {
	if tenant != "" {
		pol.CustomPatterns = append(append([]*regexp.Regexp(nil), pol.CustomPatterns...), regexp.MustCompile("(?i)"+regexp.QuoteMeta(tenant)))
	}
	return pol
}
