// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"net/http"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tags"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type netBoxTagApplyRequest struct {
	Confirmed bool             `json:"confirmed"`
	Preview   netBoxTagPreview `json:"preview"`
}

func (s *Server) authorizeNetBoxTagApply(r *http.Request, contextID, kind string) (string, error) {
	permission, err := tagSubjectReadPermission(kind)
	if err != nil {
		return "", err
	}
	var tenantID string
	for _, grant := range []string{permTagsRead, permTagsWrite, permCMDBRead, permission} {
		tenantID, err = s.authorizeTagContext(r, contextID, grant)
		if err != nil {
			return "", err
		}
	}
	return tenantID, nil
}

func (s *Server) handleApplyNetBoxTag(w http.ResponseWriter, r *http.Request) error {
	var input netBoxTagApplyRequest
	if err := decodeJSONLimit(r, tags.MaxValueInputBytes, &input); err != nil {
		return err
	}
	record, err := s.applyReviewedNetBoxTag(r, input)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, record)
	return nil
}

func (s *Server) applyReviewedNetBoxTag(r *http.Request, input netBoxTagApplyRequest) (store.TagAssignmentRecord, error) {
	contextID := r.PathValue("context_id")
	expected := input.Preview.Target
	tenantID, err := s.authorizeNetBoxTagApply(r, contextID, expected.TargetKind)
	if err != nil {
		return store.TagAssignmentRecord{}, err
	}
	if !input.Confirmed || expected.ContextID != contextID ||
		(input.Preview.Candidate.Field != "role" && input.Preview.Candidate.Field != "site") {
		return store.TagAssignmentRecord{}, apierror.BadRequest("confirm an unchanged subject preview for this context")
	}
	if err := s.cmdbReady(); err != nil {
		return store.TagAssignmentRecord{}, err
	}
	ctx := tenancy.WithTenant(r.Context(), tenancy.ID(tenantID))
	ctx, budget, done, err := beginNetBoxImport(ctx, s.flowStore, s.fairnessGate)
	if err != nil {
		return store.TagAssignmentRecord{}, err
	}
	defer done()
	r = r.WithContext(ctx)
	target, facts, err := readNetBoxTagTarget(ctx, s.pool, contextID, expected.TagID, netBoxTargetReference(expected), budget.MemoryBytes/4)
	if err != nil {
		return store.TagAssignmentRecord{}, tagAssignmentAPIError(err)
	}
	if target != expected {
		return store.TagAssignmentRecord{}, apierror.Conflict("tag import target or revision changed; request a new preview")
	}
	selected, err := s.cmdb.RecheckNetBoxSubjectTag(ctx, sourceTagFacts(facts), input.Preview.Candidate)
	if err != nil {
		return store.TagAssignmentRecord{}, netBoxTagPreviewError(err)
	}
	candidate := selected.Candidate()
	if candidate != input.Preview.Candidate {
		return store.TagAssignmentRecord{}, apierror.Conflict("NetBox tag candidate changed; request a new preview")
	}
	// Current context grants are reloaded after remote I/O. The audited write
	// then re-reads local authority and the exact revision in one RLS snapshot.
	if _, err := s.authorizeNetBoxTagApply(r, contextID, expected.TargetKind); err != nil {
		return store.TagAssignmentRecord{}, err
	}
	var record store.TagAssignmentRecord
	err = tenancy.InTenantWriteSnapshot(ctx, s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		var err error
		record, err = (store.TagAssignments{}).ApplyNetBoxTag(ctx, sc, expected, candidate.Value, candidate.SourceRef, budget.MemoryBytes/4,
			func(current store.TagImportFacts) bool { return selected.Matches(sourceTagFacts(current)) })
		if err != nil {
			return err
		}
		return s.recordAudit(ctx, sc, r, "tag.assignment.imported", record.ID, map[string]any{
			"context_id": contextID, "tag_id": record.TagID, "target_kind": record.TargetKind, "target_id": record.TargetID,
			"source": "netbox", "source_ref": record.SourceRef})
	})
	if err != nil {
		return store.TagAssignmentRecord{}, tagAssignmentAPIError(err)
	}
	return record, nil
}
