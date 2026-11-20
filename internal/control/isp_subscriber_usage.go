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

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func (s *Server) handleSubscriberUsage(w http.ResponseWriter, r *http.Request) error {
	actor := auth.PrincipalFrom(r.Context())
	if actor == nil || actor.TenantID == "" || actor.UserID == "" {
		return apierror.Unauthorized("current tenant identity is required")
	}
	var input flow.SubscriberUsageRequest
	if err := decodeJSONLimit(r, 4096, &input); err != nil {
		return err
	}
	input.ViewID = r.PathValue("id")
	if !reportRequirementUUID(input.ViewID) || !reportRequirementUUID(input.TagID) || (input.End != nil && input.End.IsZero()) {
		return apierror.Validation("select an exact saved flow view and tenant subscriber tag")
	}
	if err := input.Validate(); err != nil {
		return apierror.Validation(err.Error())
	}
	ctx := tenancy.WithTenant(r.Context(), tenancy.ID(actor.TenantID))
	ctx, flush := scopedABACDenial(ctx)
	defer flush(s)
	budget := flowstore.ExplorerQueryBudget(s.flowStore)
	if err := budget.Validate(); err != nil {
		return apierror.Unavailable("subscriber report admission is unavailable")
	}
	ctx, cancel := context.WithTimeout(ctx, budget.ExecutionLimit)
	defer cancel()
	result, err := s.captureSubscriberUsage(ctx, actor, input)
	if errors.Is(err, store.ErrIncidentImpactBudget) {
		return reportGenerationError(errors.Join(store.ErrClientReportBudget, err))
	}
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, result)
	return nil
}

func bindSubscriberUsagePlan(ctx context.Context, tenant string, value *preparedReportFlow, input flow.SubscriberUsageRequest) error {
	vocabulary, present, err := flow.QueryVocabularyFromContext(ctx, tenant)
	if err != nil {
		return err
	}
	if !present {
		return apierror.Forbidden("tenant prefix tag vocabulary is unavailable")
	}
	// The source query and its filters are already revalidated by the normal
	// capture path. Pin the added subscriber dimensions to the explicit tag ID.
	prepared := input.Plan(value.current)
	ids, err := flow.QueryViewTagIDs(prepared, vocabulary)
	if err != nil {
		return mapFlowViewError(err)
	}
	source, destination := input.TagFields()
	if ids[source] != input.TagID || ids[destination] != input.TagID {
		return apierror.NotFound("current subscriber prefix tag not found")
	}
	value.current, value.view.Definition.TagIDs = prepared, ids
	return nil
}

func (s *Server) captureSubscriberUsage(ctx context.Context, actor *auth.Principal, input flow.SubscriberUsageRequest) (flow.SubscriberUsageReport, error) {
	var out flow.SubscriberUsageReport
	options := reportFlowCaptureOptions{SubscriberUsage: &input}
	if input.IncludeLatency {
		options.ReservedMemoryBytes = flowstore.ExplorerQueryBudget(s.flowStore).MemoryBytes / 8
	}
	if input.End != nil {
		options.PeriodEnd = input.End.UTC()
	}
	sources := []reportFlowSourceRef{{ID: input.ViewID, Version: input.Version}}
	capture, err := s.captureFlowSourcesWithOptions(ctx, actor, sources, true, false, options)
	if err != nil {
		return out, err
	}
	defer capture.Close()
	if len(capture.Results) != 1 || !capture.ContextsCaptured {
		return out, apierror.Conflict("complete subscriber observation and context coverage is unavailable")
	}
	original := capture.Results[0]
	out, err = projectSubscriberUsage(ctx, input, original)
	if err != nil {
		return out, err
	}
	var contexts []string
	for _, item := range capture.Contexts {
		contexts = append(contexts, item.ContextID)
	}
	var latency *subscriberLatencyCapture
	if input.IncludeLatency {
		// Reserve space for retained source rows, retained observations and the
		// projection before admitting the flow query.
		out.Latency, latency, err = s.captureSubscriberLatency(ctx, actor, contexts, input, out.From, out.To, options.ReservedMemoryBytes/4)
		if err != nil {
			return out, reportGenerationError(err)
		}
		out.LatencyIncluded = true
	}
	err = tenancy.InTenant(tenancy.WithSiloTableLock(ctx), s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		if err := audit.LockTenantStream(ctx, sc.Q, sc.Tenant.String()); err != nil {
			return err
		}
		ctx = store.WithReportSourceAuditLock(ctx, sc)
		if err := s.validateReportSourcePublication(ctx, sc, actor, capture); err != nil {
			return err
		}
		current, err := store.SubscriberAssignmentInScope(ctx, sc, contexts, input.TagID, input.TagKey, input.Subscriber)
		if errors.Is(err, store.ErrSubscriberAssignmentUnavailable) {
			return apierror.NotFound("current subscriber prefix assignment not found")
		}
		if err != nil {
			return err
		}
		if current.UsesRules || current.Revision != original.Result.TagRevision || current.StableSince.IsZero() || current.StableSince.After(out.From) {
			return apierror.Conflict("choose an interval covered by the current explicit subscriber assignments")
		}
		return s.verifySubscriberLatency(ctx, sc, actor, latency)
	})
	return out, reportGenerationError(err)
}
