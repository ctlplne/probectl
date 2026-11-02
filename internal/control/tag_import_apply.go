// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"net/http"
	"time"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tags"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type netBoxTagApplyRequest struct {
	Confirmed bool             `json:"confirmed"`
	Preview   netBoxTagPreview `json:"preview"`
}

func (s *Server) authorizeNetBoxTagApply(r *http.Request, contextID string) (string, error) {
	var tenantID string
	for _, permission := range []string{permTagsRead, permTagsWrite, permCMDBRead} {
		var err error
		tenantID, err = s.authorizeTagContext(r, contextID, permission)
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
	tenantID, err := s.authorizeNetBoxTagApply(r, contextID)
	if err != nil {
		return store.TagAssignmentRecord{}, err
	}
	expected := input.Preview.Target
	if !input.Confirmed || expected.ContextID != contextID || expected.TargetKind != "exporter" ||
		(input.Preview.Candidate.Field != "role" && input.Preview.Candidate.Field != "site") {
		return store.TagAssignmentRecord{}, apierror.BadRequest("confirm an unchanged exporter preview for this context")
	}
	var target store.NetBoxTagTarget
	if err := s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
		var err error
		target, err = (store.TagAssignments{}).NetBoxExporterTarget(ctx, sc,
			contextID, expected.TagID, expected.ExporterAgentID, expected.ExporterSourceRef)
		return err
	}); err != nil {
		return store.TagAssignmentRecord{}, tagAssignmentAPIError(err)
	}
	if target != expected {
		return store.TagAssignmentRecord{}, apierror.Conflict("tag import target or revision changed; request a new preview")
	}
	if err := s.cmdbReady(); err != nil {
		return store.TagAssignmentRecord{}, err
	}
	ctx, cancel := context.WithTimeout(tenancy.WithTenant(r.Context(), tenancy.ID(tenantID)), 15*time.Second)
	defer cancel()
	r = r.WithContext(ctx)
	candidate, err := s.cmdb.PreviewNetBoxTag(ctx, target.ExporterSourceRef, input.Preview.Candidate.Field)
	if err != nil {
		return store.TagAssignmentRecord{}, netBoxTagPreviewError(err)
	}
	if candidate != input.Preview.Candidate {
		return store.TagAssignmentRecord{}, apierror.Conflict("NetBox tag candidate changed; request a new preview")
	}
	// Recheck context authorization after external I/O, before the audited write.
	if _, err := s.authorizeNetBoxTagApply(r, contextID); err != nil {
		return store.TagAssignmentRecord{}, err
	}
	var record store.TagAssignmentRecord
	err = s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
		var err error
		record, err = (store.TagAssignments{}).ApplyNetBoxExporter(ctx, sc, expected,
			candidate.Value, candidate.SourceRef)
		if err != nil {
			return err
		}
		return s.recordAudit(ctx, sc, r, "tag.assignment.imported", record.ID,
			map[string]any{"context_id": contextID, "tag_id": record.TagID,
				"target_kind": record.TargetKind, "target_id": record.TargetID,
				"source": "netbox", "source_ref": record.SourceRef})
	})
	if err != nil {
		return store.TagAssignmentRecord{}, tagAssignmentAPIError(err)
	}
	return record, nil
}
