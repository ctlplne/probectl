// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"encoding/json"

	"github.com/ctlplne/probectl/internal/ai"
	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/incident"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
)

// This operation-local callback retains original selectors, never a reusable
// grant. Export invokes it after encoding/signing and before disclosure; it
// rechecks current authority and original documents without rerunning history.
type incidentEvidenceFinalizer func(context.Context) error

func (s *Server) exportIncidentVerdict(ctx context.Context, actor *auth.Principal, inc *incident.Incident, input incident.VerdictInput, memory int64, publication *incidentEvidenceFinalizer) (*incident.FaultVerdict, error) {
	if actor == nil || inc == nil || inc.TenantID != actor.TenantID {
		return nil, apierror.Forbidden("incident export requires its current tenant identity")
	}
	budget := flowstore.ExplorerOperationBudget(ctx, s.flowStore)
	if err := budget.Validate(); err != nil {
		return nil, apierror.Unavailable("incident verdict export admission is unavailable")
	}
	if memory == 0 {
		memory = budget.MemoryBytes / 2
	}
	if memory <= 0 || memory > budget.MemoryBytes/2 {
		return nil, apierror.Unavailable("incident verdict export memory is unavailable")
	}
	ctx = context.WithValue(ctx, incidentImpactExportKey{}, true)
	var snapshot *store.IncidentImpactInputs
	result, err := s.computeIncidentVerdictWithPublication(ctx, actor, inc.ID, input.From, input.To, memory, &snapshot, publication)
	if err != nil {
		return nil, err
	}
	if err := requireImpactIncidentHeader(actor.TenantID, inc, snapshot); err != nil {
		return nil, err
	}
	redacted, err := redactIncidentVerdict(result, redactionPolicy(s.cfg), actor.TenantID)
	if err != nil {
		return nil, err
	}
	return &redacted, nil
}

func redactIncidentVerdict(value incident.FaultVerdict, pol ai.RedactionPolicy, tenant string) (incident.FaultVerdict, error) {
	pol = incidentEvidenceTenantPolicy(pol, tenant)
	body, err := json.Marshal(value)
	if err != nil {
		return incident.FaultVerdict{}, err
	}
	var out incident.FaultVerdict
	if err := json.Unmarshal(body, &out); err != nil {
		return out, err
	}
	for i := range out.Hypotheses {
		for _, citations := range [][]incident.VerdictCitation{out.Hypotheses[i].For, out.Hypotheses[i].Against} {
			for j := range citations {
				citations[j].AgentID = ai.RedactTextForTenant(citations[j].AgentID, pol, tenant)
			}
		}
	}
	return out, nil
}
