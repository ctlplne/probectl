// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/cmdb"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type netBoxTagPreviewRequest struct {
	TagID             string `json:"tag_id"`
	ExporterAgentID   string `json:"exporter_agent_id"`
	ExporterSourceRef string `json:"exporter_source_ref"`
	Field             string `json:"field"`
}

type netBoxTagPreview struct {
	Target    store.NetBoxTagTarget   `json:"target"`
	Candidate cmdb.NetBoxTagCandidate `json:"candidate"`
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
	if input.Field != "role" && input.Field != "site" {
		return apierror.BadRequest("NetBox tag field must be role or site")
	}
	var target store.NetBoxTagTarget
	if err := s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
		var err error
		target, err = (store.TagAssignments{}).NetBoxExporterTarget(ctx, sc, contextID,
			input.TagID, input.ExporterAgentID, input.ExporterSourceRef)
		return err
	}); err != nil {
		return tagAssignmentAPIError(err)
	}
	if err := s.cmdbReady(); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(tenancy.WithTenant(r.Context(), tenancy.ID(tenantID)), 15*time.Second)
	defer cancel()
	candidate, err := s.cmdb.PreviewNetBoxTag(ctx, target.ExporterSourceRef, input.Field)
	if err != nil {
		return netBoxTagPreviewError(err)
	}
	writeJSON(w, http.StatusOK, netBoxTagPreview{Target: target, Candidate: candidate})
	return nil
}

func netBoxTagPreviewError(err error) error {
	if errors.Is(err, cmdb.ErrNoTagCandidate) {
		return apierror.NotFound("no unambiguous NetBox tag candidate for the owned exporter")
	}
	return apierror.Unavailable("NetBox tag preview source or tenant binding is unavailable")
}
