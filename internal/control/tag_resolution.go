// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/fairness"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tags"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func tagSubjectQuery(query url.Values) (store.TagSubjectReference, error) {
	for key, values := range query {
		switch key {
		case "target_kind", "target_id", "exporter_agent_id", "exporter_source_ref":
		default:
			return store.TagSubjectReference{}, apierror.BadRequest("unknown tag subject parameter")
		}
		if len(values) != 1 || values[0] == "" {
			return store.TagSubjectReference{}, apierror.BadRequest("tag subject parameters must be single nonempty values")
		}
	}
	return store.TagSubjectReference{Kind: query.Get("target_kind"), ID: query.Get("target_id"),
		ExporterAgentID: query.Get("exporter_agent_id"), ExporterSourceRef: query.Get("exporter_source_ref")}, nil
}

func (s *Server) handleResolveSubjectTags(w http.ResponseWriter, r *http.Request) error {
	contextID := r.PathValue("context_id")
	tenantID, err := s.authorizeTagContext(r, contextID, permTagsRead)
	if err != nil {
		return err
	}
	if len(r.URL.RawQuery) > 8<<10 {
		return apierror.BadRequest("tag subject query exceeds the input bound")
	}
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return apierror.BadRequest("invalid tag subject parameters")
	}
	ref, err := tagSubjectQuery(query)
	if err != nil {
		return err
	}
	permission, err := tagSubjectReadPermission(ref.Kind)
	if err != nil {
		return err
	}
	if _, err := s.authorizeTagContext(r, contextID, permission); err != nil {
		return err
	}
	ctx := tenancy.WithTenant(r.Context(), tenancy.ID(tenantID))
	out, err := resolveSubjectTags(ctx, s.pool, s.flowStore, s.fairnessGate,
		tags.Scope{TenantID: tenantID, ContextID: contextID}, ref)
	if err != nil {
		return tagQueryResponseError(w, err)
	}
	writeJSON(w, http.StatusOK, out)
	return nil
}

// Effective matches can disclose properties of their source. A tag grant
// alone must not turn this endpoint into a source-permission bypass.
func tagSubjectReadPermission(kind string) (string, error) {
	switch kind {
	case "device", "interface":
		return entitySourcePermission(entity.DeviceTarget), nil
	case "prefix":
		return "entities.read", nil
	case "agent":
		return entitySourcePermission(entity.AgentSite), nil
	case "test":
		return entitySourcePermission(entity.PathAgent), nil
	case "exporter":
		return entitySourcePermission(entity.FlowExporter), nil
	default:
		return "", apierror.BadRequest("invalid tag subject kind")
	}
}

// Both transports authorize the current context before entering this common
// bounded read. The store rechecks all ownership under the tenant application
// role and returns no partially resolved metadata on refusal.
func resolveSubjectTags(ctx context.Context, pool *pgxpool.Pool, flowStore flowstore.Store, gate *fairness.Gate, scope tags.Scope, ref store.TagSubjectReference) (tags.SubjectResolution, error) {
	budget := flowstore.ExplorerOperationBudget(ctx, flowStore)
	if err := budget.Validate(); err != nil {
		return tags.SubjectResolution{}, apierror.Unavailable("tag query cost policy is unavailable")
	}
	ctx, cancel := context.WithTimeout(ctx, budget.ExecutionLimit)
	defer cancel()
	if gate != nil {
		done, err := gate.BeginQuery(ctx, scope.TenantID)
		if err != nil {
			return tags.SubjectResolution{}, tagQueryAdmissionError(err)
		}
		defer done()
	}
	resolved, err := store.NewTagSnapshots(pool).ResolveSubject(ctx, scope, ref, budget.MemoryBytes/4)
	if err != nil {
		return tags.SubjectResolution{}, tagSubjectAPIError(err)
	}
	out := projectSubjectTags(resolved)
	encoded, err := json.Marshal(out)
	if err != nil || int64(len(encoded)) > budget.ResponseBytes || int64(len(encoded)) > budget.MemoryBytes/2 {
		return tags.SubjectResolution{}, apierror.Validation("effective tags exceed the query response budget")
	}
	if err := ctx.Err(); err != nil {
		return tags.SubjectResolution{}, tagSubjectAPIError(err)
	}
	return out, nil
}

func projectSubjectTags(resolved store.ResolvedTagSubject) tags.SubjectResolution {
	out := tags.SubjectResolution{ContextID: resolved.Scope.ContextID, TargetKind: resolved.Kind,
		TargetID: resolved.ID, TagRevision: strconv.FormatInt(resolved.Revision, 10),
		AsOf: resolved.AsOf.UTC().Format(time.RFC3339Nano), Items: []tags.EffectiveItem{}}
	if resolved.Kind == "exporter" {
		out.TargetID = ""
	}
	for _, item := range resolved.Items {
		out.Items = append(out.Items, tags.EffectiveItem{TagID: item.TagID, Key: item.Key, Value: item.Value, Source: item.Source})
	}
	return out
}

func tagSubjectAPIError(err error) error {
	switch {
	case errors.Is(err, tags.ErrInvalid), errors.Is(err, tags.ErrScopeMismatch):
		return apierror.BadRequest("invalid tag subject or routing context")
	case errors.Is(err, pgx.ErrNoRows):
		return apierror.NotFound("subject does not exist in this tenant routing context")
	case errors.Is(err, store.ErrTagSubjectFactsAmbiguous):
		return apierror.Conflict("current subject facts conflict; effective tags are unavailable")
	case errors.Is(err, store.ErrTagSnapshotBudget):
		return apierror.Validation("effective tags exceed the query memory budget")
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return apierror.Unavailable("effective tag query was canceled or exceeded its execution budget")
	default:
		return apierror.Unavailable("effective tag snapshot is unavailable")
	}
}
