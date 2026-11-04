// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"encoding/json"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ctlplne/probectl/internal/ai"
	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/reporting"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tags"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type reportFlowBatchKey struct{}

// The existing registry has at most 64 keys, each expanded to seven fields.
// Reserve their strings, operator slices and map storage before the schema read;
// retain that charge alongside prepared definitions until the capture ends.
const reportFlowPreparationReserve = int64(tags.MaxDefinitions) * 8192

type reportFlowSourceRef struct {
	ID      string `json:"id"`
	Version string `json:"version"`
}

type reportFlowInput struct {
	ID          string    `json:"id"`
	Version     string    `json:"version"`
	Period      string    `json:"period"`
	TagRevision string    `json:"tag_revision,omitempty"`
	From        time.Time `json:"from"`
	To          time.Time `json:"to"`
	TagAsOf     time.Time `json:"tag_as_of,omitempty"`
}

// The caller owns the capture and must Close after staging/publication. Values
// are frozen records; the requirements never stand in for current reader grants.
type reportFlowCapture struct {
	TenantID         string
	Tables           []reporting.CSVTable
	Inputs           []reportFlowInput
	Permissions      []string
	Contexts         []reportContextRequirement
	ContextsCaptured bool
	release          func()
	once             sync.Once
}

func (c *reportFlowCapture) Close() {
	if c != nil && c.release != nil {
		c.once.Do(c.release)
	}
}

type preparedReportFlow struct {
	view     flow.SavedQueryView
	current  flow.QueryPlan
	previous *flow.QueryPlan
	versions map[string]int64
}

func (p preparedReportFlow) executions() int {
	if p.previous == nil {
		return 1
	}
	if p.current.View == "matrix" {
		return 6
	}
	return 4
}

// captureReportFlowSources reads real source results without adopting private
// snapshot ownership or performing a saved-query preference write. No public
// source route is exposed until configuration and recipient wiring is complete.
func (s *Server) captureReportFlowSources(ctx context.Context, actor *auth.Principal, refs []reportFlowSourceRef) (_ *reportFlowCapture, resultErr error) {
	bound, ok := tenancy.FromContext(ctx)
	if !ok || actor == nil || bound.String() != actor.TenantID || actor.UserID == "" {
		return nil, apierror.Forbidden("report source identity is unavailable")
	}
	if s.pool == nil || s.flowQueryViews == nil || s.fairnessGate == nil || len(refs) == 0 {
		return nil, apierror.Unavailable("report source admission is unavailable")
	}
	budget := flowstore.ExplorerQueryBudget(s.flowStore)
	if err := budget.Validate(); err != nil {
		return nil, apierror.Unavailable("report source cost policy is unavailable")
	}
	if budget.MemoryBytes/4 < reportFlowPreparationReserve {
		return nil, reportProjectionLimit()
	}
	release, err := s.fairnessGate.BeginQuery(ctx, actor.TenantID)
	if err != nil {
		return nil, err
	}
	defer func() {
		if resultErr != nil {
			release()
		}
	}()
	ctx, cancel := context.WithTimeout(ctx, budget.ExecutionLimit)
	defer cancel()
	current, err := loadCurrentUserAuthority(ctx, s.pool, actor.TenantID, actor.UserID)
	if err != nil {
		return nil, err
	}
	ctx, principal, err := current.requestContext(ctx, actor)
	if err != nil {
		return nil, err
	}
	if _, err := s.authorizeFlowViewPrincipal(ctx, principal, false); err != nil {
		return nil, err
	}
	ctx, err = s.withFlowViewVocabulary(ctx, principal)
	if err != nil {
		return nil, err
	}
	at := time.Now().UTC()
	prepared, cost, count, err := s.prepareReportFlows(ctx, principal, refs, at, budget.MemoryBytes/4)
	if err != nil {
		return nil, err
	}
	// In addition to retained per-plan results, reserve three shares for the
	// metadata snapshot/projections, schema/context requirements and frozen table
	// projection. These do not add queries or any source-read allowance.
	batch, err := flowstore.NewPlanBatch(ctx, s.flowStore, principal.TenantID, count, 3)
	if err != nil {
		return nil, flowExplorerStoreError(err)
	}
	defer batch.Close()
	ctx = context.WithValue(batch.Context(), reportFlowBatchKey{}, batch)
	workspace := flowstore.ExplorerOperationBudget(ctx, s.flowStore).MemoryBytes
	if cost > workspace/4 {
		return nil, reportProjectionLimit()
	}
	capture, err := s.collectReportFlows(ctx, principal, prepared, at, workspace)
	if err != nil {
		return nil, err
	}
	capture.release = release
	return capture, nil
}

func (s *Server) prepareReportFlows(ctx context.Context, p *auth.Principal, refs []reportFlowSourceRef, at time.Time, limit int64) ([]preparedReportFlow, int64, int, error) {
	if limit < reportFlowPreparationReserve || int64(len(refs)) > (limit-reportFlowPreparationReserve)/256 {
		return nil, 0, 0, reportProjectionLimit()
	}
	seen := make(map[string]bool, len(refs))
	prepared := make([]preparedReportFlow, 0, len(refs))
	used := reportFlowPreparationReserve
	count := 0
	for _, ref := range refs {
		if ref.ID == "" || strings.TrimSpace(ref.ID) != ref.ID || seen[ref.ID] {
			return nil, 0, 0, apierror.Validation("report source references require distinct exact identities")
		}
		if _, err := flow.QueryViewVersion(ref.Version); err != nil {
			return nil, 0, 0, apierror.Validation("report source requires its exact saved-query version")
		}
		seen[ref.ID] = true
		item, err := s.flowQueryViews.GetQueryView(ctx, p.TenantID, p.UserID, ref.ID)
		if err != nil {
			return nil, 0, 0, s.mapFlowViewStoreError(ctx, p, err)
		}
		if item.Version != ref.Version {
			return nil, 0, 0, apierror.Conflict("report source changed; refresh its exact version")
		}
		if err := s.authorizeFlowViewContext(ctx, p, item); err != nil {
			return nil, 0, 0, err
		}
		encoded, err := json.Marshal(item.Definition)
		if err != nil || int64(len(encoded))*2+256 > limit-used {
			return nil, 0, 0, reportProjectionLimit()
		}
		used += int64(len(encoded))*2 + 256
		value, err := s.prepareReportFlow(ctx, p, item, at)
		if err != nil {
			return nil, 0, 0, err
		}
		if count > int(^uint(0)>>1)-value.executions() {
			return nil, 0, 0, reportProjectionLimit()
		}
		count += value.executions()
		prepared = append(prepared, value)
	}
	return prepared, used, count, ctx.Err()
}

func (s *Server) prepareReportFlow(ctx context.Context, p *auth.Principal, item flow.SavedQueryView, at time.Time) (preparedReportFlow, error) {
	vocabulary, bound, err := flow.QueryVocabularyFromContext(ctx, p.TenantID)
	if err != nil {
		return preparedReportFlow{}, err
	}
	var plan flow.QueryPlan
	var previous *flow.QueryPlan
	if bound {
		plan, previous, err = flow.MaterializeQueryViewWithVocabulary(item.Definition, at, vocabulary)
	} else {
		plan, previous, err = flow.MaterializeQueryView(item.Definition, at)
	}
	if err != nil {
		return preparedReportFlow{}, apierror.Validation("report source cannot be materialized")
	}
	var resolved flow.ResolvedQueryFilters
	if bound {
		resolved, err = flow.ResolveQueryFiltersWithVocabulary(ctx, p.TenantID, plan.Filter, s.flowQueryFilters, "", vocabulary)
	} else {
		resolved, err = flow.ResolveQueryFilters(ctx, p.TenantID, plan.Filter, s.flowQueryFilters, "")
	}
	if err != nil {
		return preparedReportFlow{}, apierror.Validation("report source filters are unavailable")
	}
	plan.Filter = resolved.Expression
	if previous != nil {
		previous.Filter = resolved.Expression
	}
	return preparedReportFlow{view: item, current: plan, previous: previous, versions: resolved.Versions}, nil
}

func reportPreparedSubjects(prepared []preparedReportFlow) (bool, []string) {
	usesTags := false
	set := map[string]bool{}
	for _, value := range prepared {
		fields := append(append(append([]string(nil), value.current.GroupBy...), value.current.MatrixWith...), flow.QueryFilterFields(value.current.Filter)...)
		for _, field := range fields {
			usesTags = usesTags || strings.HasPrefix(field, "tag.")
		}
		for _, subject := range relatedFlowTagSubjects(fields) {
			set[subject] = true
		}
	}
	subjects := make([]string, 0, len(set))
	for subject := range set {
		subjects = append(subjects, subject)
	}
	sort.Strings(subjects)
	return usesTags, subjects
}

func (s *Server) collectReportFlows(ctx context.Context, p *auth.Principal, prepared []preparedReportFlow, at time.Time, workspace int64) (*reportFlowCapture, error) {
	batch, ok := ctx.Value(reportFlowBatchKey{}).(*flowstore.PlanBatch)
	if !ok || batch == nil {
		return nil, apierror.Unavailable("report source batch is unavailable")
	}
	ctx = context.WithValue(ctx, reportFlowBatchKey{}, batch)
	usesTags, subjects := reportPreparedSubjects(prepared)
	scope := &reportContextCapture{tenant: p.TenantID, remaining: workspace / 4}
	var tagAsOf time.Time
	if usesTags {
		data, err := s.loadFlowTagQuery(context.WithValue(ctx, reportContextCaptureKey{}, scope), p, subjects...)
		if err != nil {
			return nil, err
		}
		if !scope.captured {
			return nil, apierror.Unavailable("report metadata scope was not captured")
		}
		tagAsOf = time.Now().UTC()
		ctx = flowTagQueryContext(ctx, data)
		vocabulary, err := data.Vocabulary(p.TenantID)
		if err != nil {
			return nil, err
		}
		ctx, err = flow.WithQueryVocabulary(ctx, p.TenantID, vocabulary)
		if err != nil {
			return nil, err
		}
	}
	captures := make([]capturedReportFlow, 0, len(prepared)*2)
	permissions := map[string]bool{permAIQuery: true, permFlowRead: true}
	if usesTags {
		permissions[permTagsRead] = true
	}
	for _, value := range prepared {
		current, err := s.reportSourceQuery(ctx, p, value, value.current, at)
		if err != nil {
			return nil, err
		}
		needed, err := flowPlanPermissions(ctx, p.TenantID, *current.Flow)
		if err != nil {
			return nil, err
		}
		for _, permission := range needed {
			permissions[permission] = true
		}
		var now, before flowstore.PlanResult
		if value.previous == nil {
			now, err = s.recordFlowSpec(ctx, p.TenantID, *current.Flow, nil)
			now.SavedFilterVersions = value.versions
		} else {
			previous, queryErr := s.reportSourceQuery(ctx, p, value, *value.previous, at)
			if queryErr != nil {
				return nil, queryErr
			}
			comparison, queryErr := s.collectFlowComparison(ctx, p, current, previous, value.versions)
			if queryErr != nil {
				return nil, queryErr
			}
			if comparison.Flow == nil {
				return nil, apierror.Unavailable("complete report comparison is unavailable")
			}
			now, before = comparison.Flow.Current, comparison.Flow.Previous
		}
		if err != nil {
			return nil, err
		}
		captures = append(captures, reportFlowResult(p.TenantID, value.view, "current", now, tagAsOf))
		if value.previous != nil {
			captures = append(captures, reportFlowResult(p.TenantID, value.view, "previous", before, tagAsOf))
		}
	}
	tables, err := projectReportFlowRecords(ctx, captures, workspace/4, reporting.DefaultCSVLimits().TableRows)
	if err != nil {
		return nil, err
	}
	result := &reportFlowCapture{TenantID: p.TenantID, Tables: tables, Contexts: scope.contexts, ContextsCaptured: scope.captured}
	for permission := range permissions {
		result.Permissions = append(result.Permissions, permission)
	}
	sort.Strings(result.Permissions)
	for _, capture := range captures {
		input := reportFlowInput{ID: capture.ID, Version: capture.Version, Period: capture.Period, From: capture.Result.Query.From, To: capture.Result.Query.To, TagAsOf: capture.TagAsOf}
		if capture.Result.TagRevision > 0 {
			input.TagRevision = strconv.FormatInt(capture.Result.TagRevision, 10)
		}
		result.Inputs = append(result.Inputs, input)
	}
	return result, ctx.Err()
}

func reportFlowResult(tenant string, view flow.SavedQueryView, period string, result flowstore.PlanResult, captured time.Time) capturedReportFlow {
	if result.TagRevision == 0 {
		captured = time.Time{}
	}
	return capturedReportFlow{TenantID: tenant, ID: view.ID, Version: view.Version, Name: view.Definition.Name, Period: period, Result: result, TagAsOf: captured}
}

func (s *Server) reportSourceQuery(ctx context.Context, p *auth.Principal, value preparedReportFlow, plan flow.QueryPlan, at time.Time) (ai.ExplorerQuery, error) {
	vocabulary, bound, err := flow.QueryVocabularyFromContext(ctx, p.TenantID)
	if err != nil {
		return ai.ExplorerQuery{}, err
	}
	if bound {
		if err := flow.VerifyQueryViewTagIDs(value.view.Definition.TagIDs, plan, vocabulary); err != nil {
			return ai.ExplorerQuery{}, mapFlowViewError(err)
		}
	} else if len(value.view.Definition.TagIDs) > 0 {
		return ai.ExplorerQuery{}, apierror.Forbidden("report source metadata access is unavailable")
	}
	if err := s.authorizeFlowMetadata(ctx, p, plan); err != nil {
		return ai.ExplorerQuery{}, err
	}
	query := ai.ExplorerQuery{Question: value.view.Definition.Name, Source: ai.ExplorerFlow, Flow: &plan}
	if bound {
		query, err = ai.NormalizeExplorerQueryWithVocabulary(query, at, vocabulary)
	} else {
		query, err = ai.NormalizeExplorerQuery(query, at)
	}
	if err != nil || query.Flow == nil {
		return ai.ExplorerQuery{}, apierror.Validation("report source cannot be normalized")
	}
	return query, nil
}
