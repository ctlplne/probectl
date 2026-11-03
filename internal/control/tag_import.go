// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"errors"
	"net/http"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/cmdb"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type netBoxTagPreviewRequest struct {
	TagID             string `json:"tag_id"`
	TargetKind        string `json:"target_kind,omitempty"`
	TargetID          string `json:"target_id,omitempty"`
	ExporterAgentID   string `json:"exporter_agent_id,omitempty"`
	ExporterSourceRef string `json:"exporter_source_ref,omitempty"`
	SourceID          string `json:"source_id,omitempty"`
	Field             string `json:"field"`
}

type netBoxTagPreview struct {
	Target    store.NetBoxTagTarget   `json:"target"`
	Candidate cmdb.NetBoxTagCandidate `json:"candidate"`
}

func (i netBoxTagPreviewRequest) reference() store.TagSubjectReference {
	kind := i.TargetKind
	if kind == "" {
		kind = "exporter"
	}
	return store.TagSubjectReference{Kind: kind, ID: i.TargetID, ExporterAgentID: i.ExporterAgentID, ExporterSourceRef: i.ExporterSourceRef}
}

func (s *Server) handlePreviewNetBoxTag(w http.ResponseWriter, r *http.Request) error {
	contextID := r.PathValue("context_id")
	tenantID, err := s.authorizeTagContext(r, contextID, permTagsRead)
	if err != nil {
		return err
	}
	if _, err := s.authorizeTagContext(r, contextID, permCMDBRead); err != nil {
		return err
	}
	var input netBoxTagPreviewRequest
	if err := decodeJSONLimit(r, 8<<10, &input); err != nil {
		return err
	}
	permission, err := tagSubjectReadPermission(input.reference().Kind)
	if err != nil {
		return err
	}
	if _, err := s.authorizeTagContext(r, contextID, permission); err != nil {
		return err
	}
	if input.Field != "role" && input.Field != "site" {
		return apierror.BadRequest("NetBox tag field must be role or site")
	}
	if err := s.cmdbReady(); err != nil {
		return err
	}
	ctx := tenancy.WithTenant(r.Context(), tenancy.ID(tenantID))
	ctx, budget, done, err := beginNetBoxImport(ctx, s.flowStore, s.fairnessGate)
	if err != nil {
		return tagQueryResponseError(w, err)
	}
	defer done()
	target, facts, err := readNetBoxTagTarget(ctx, s.pool, contextID, input.TagID, input.reference(), budget.MemoryBytes/4)
	if err != nil {
		return tagAssignmentAPIError(err)
	}
	selection, err := s.cmdb.PreviewNetBoxSubjectTag(ctx, sourceTagFacts(facts), input.Field, input.SourceID)
	if err != nil {
		return netBoxTagPreviewError(err)
	}
	result := netBoxTagPreview{Target: target, Candidate: selection.Candidate()}
	if err := netBoxImportResponseBudget(result, budget); err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, result)
	return nil
}

func netBoxTagPreviewError(err error) error {
	if errors.Is(err, cmdb.ErrNoTagCandidate) {
		return apierror.NotFound("no unambiguous NetBox tag candidate for the owned subject; select an exact source ID when needed")
	}
	return apierror.Unavailable("NetBox tag preview source or tenant binding is unavailable")
}
