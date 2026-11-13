// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"sync"
	"time"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/reporting"
	"github.com/ctlplne/probectl/internal/slo"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type clientReportCapture struct {
	TenantID      string
	From, To      time.Time
	Sources       []store.IncidentConfiguredTest
	Definitions   []slo.SLO
	SLOEnabled    bool
	Availability  []clientReportAvailability
	SLOs          []clientReportSLO
	Tables        []reporting.CSVTable
	Events        *clientReportEventCapture
	Verdicts      []clientReportVerdict
	Capacity      []clientReportCapacityCapture
	InputsDigest  string
	retainedBytes int64
	release       func()
}

func (c *clientReportCapture) close() {
	if c != nil && c.release != nil {
		c.release()
	}
}

// Capture keeps the existing fairness slot until publication/discard. Source
// selection, current credential ceiling and the complete original scan share
// one RLS read snapshot. It changes neither live health nor historical sender
// validity: the common original reader owns both existing certificate checks.
func (s *Server) captureClientReportSources(ctx context.Context, actor *auth.Principal, month string, at time.Time, budget flowstore.ExplorerBudget, capacityTargets ...reporting.ClientReportCapacityTarget) (_ *clientReportCapture, captureErr error) {
	bound, ok := tenancy.FromContext(ctx)
	if !ok || actor == nil || actor.UserID == "" || bound.String() != actor.TenantID {
		return nil, entity.ErrScopeMismatch
	}
	from, to, err := reporting.ClientReportMonth(month, at)
	if err != nil {
		return nil, apierror.Validation("monthly test capture requires a completed UTC calendar month")
	}
	if s.pool == nil || s.fairnessGate == nil || budget.Validate() != nil {
		return nil, apierror.Unavailable("monthly report source admission is unavailable")
	}
	ctx, err = bindFlowRoleContext(ctx, actor)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, budget.ExecutionLimit)
	defer cancel()
	if err := s.currentReportTenant(ctx, actor.TenantID); err != nil {
		return nil, err
	}
	release, err := s.fairnessGate.BeginQuery(ctx, actor.TenantID)
	if err != nil {
		return nil, err
	}
	result := &clientReportCapture{TenantID: actor.TenantID, From: from, To: to, release: sync.OnceFunc(release)}
	defer func() {
		if captureErr != nil {
			result.close()
		}
	}()
	ctx, flush := scopedABACDenial(ctx)
	defer flush(s)
	err = tenancy.InTenantReadSnapshot(ctx, s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		current, err := readCurrentUserAuthorityScope(ctx, sc, actor.UserID)
		if err != nil {
			return err
		}
		ctx, principal, err := current.requestContext(ctx, actor)
		if err != nil {
			return err
		}
		if err := s.authorizeClientReportTests(ctx, principal, map[string]string{auth.ResourceTenantKey: principal.TenantID}); err != nil {
			return err
		}
		authorize := func(ctx context.Context, record entity.ContextRecord, member store.IncidentImpactEntity, testID string) error {
			if record.TenantID != principal.TenantID || record.ContextID != member.ContextID {
				return entity.ErrScopeMismatch
			}
			resource := entityContextResource(record)
			resource["entity_id"], resource["test_id"] = member.EntityID, testID
			return s.authorizeClientReportTests(ctx, principal, resource)
		}
		result.Sources, err = store.NewEntityRegistry(s.pool).ClientReportConfiguredTestsInScope(ctx, sc, budget.MemoryBytes/8, authorize)
		if err != nil {
			return err
		}
		if s.sloEngine != nil {
			result.SLOEnabled, result.Definitions = true, s.sloEngine.SLOsFor(principal.TenantID)
		}
		accumulator, err := newClientReportSLIAccumulator(ctx, principal.TenantID, result.Sources, result.Definitions, from, to, budget.MemoryBytes/8, budget.ReadBytes)
		if err != nil {
			return err
		}
		limits := store.ConfiguredMeasurementScanBudget{MemoryBytes: budget.MemoryBytes / 8, ReadBytes: budget.ReadBytes, ReadRows: int64(budget.ReadRows)}
		if err := store.NewEntityRegistry(s.pool).WalkConfiguredTestMeasurementsInScope(ctx, sc, result.Sources, accumulator.first, to, limits, func(item store.IncidentTestMeasurement) error {
			return accumulator.observe(ctx, item)
		}); err != nil {
			return err
		}
		result.Availability, result.SLOs, err = accumulator.finish(ctx)
		if err != nil {
			return err
		}
		result.Events, err = s.captureClientReportEventsInScope(ctx, sc, principal, from, to, budget.MemoryBytes/4)
		return err
	})
	if err != nil {
		return nil, err
	}
	state := struct {
		Domain       string
		TenantID     string
		From, To     time.Time
		Sources      []store.IncidentConfiguredTest
		Definitions  []slo.SLO
		SLOEnabled   bool
		Availability []clientReportAvailability
		SLOs         []clientReportSLO
		Events       *clientReportEventCapture
	}{"probectl.client-report.inputs.v1", result.TenantID, from, to, result.Sources, result.Definitions, result.SLOEnabled, result.Availability, result.SLOs, result.Events}
	body, err := json.Marshal(state)
	if err != nil {
		return nil, err
	}
	// Retained source state and a full projection share occupy at most half
	// the operation. Rendering/final rechecks keep the other half available.
	result.retainedBytes = 4096 + 8*int64(len(body)) + budget.MemoryBytes/8
	remaining := budget.MemoryBytes/2 - result.retainedBytes
	if remaining <= 0 {
		return nil, store.ErrClientReportBudget
	}
	before := remaining
	result.Verdicts, err = s.captureClientReportVerdicts(ctx, actor, result, &remaining)
	if err != nil {
		return nil, err
	}
	result.retainedBytes += before - remaining
	before = remaining
	result.Capacity, err = s.captureClientReportCapacity(ctx, actor, result, capacityTargets, budget, &remaining)
	if err != nil {
		return nil, err
	}
	result.retainedBytes += before - remaining
	result.Tables, err = projectClientReportSLIs(ctx, result.TenantID, from, to, result.Availability, result.SLOs, budget.MemoryBytes/32)
	if err != nil {
		return nil, err
	}
	eventTables, err := projectClientReportEvents(ctx, result, budget.MemoryBytes/16)
	if err != nil {
		return nil, err
	}
	result.Tables = append(result.Tables, eventTables...)
	capacityTable, err := projectClientReportCapacity(ctx, result, budget.MemoryBytes/32)
	if err != nil {
		return nil, err
	}
	result.Tables = append(result.Tables, capacityTable)
	digest := crypto.Hash(body)
	for _, verdict := range result.Verdicts {
		digest = crypto.Hash(append(digest, []byte(verdict.SourceDigest)...))
	}
	for _, capacity := range result.Capacity {
		digest = crypto.Hash(append(digest, []byte(capacity.OriginalsDigest)...))
	}
	result.InputsDigest = hex.EncodeToString(digest)
	return result, nil
}

func (s *Server) authorizeClientReportTests(ctx context.Context, actor *auth.Principal, resource map[string]string) error {
	for _, permission := range []string{"metrics.read", "entities.read", permTestRead} {
		if err := s.authorize(ctx, actor, permission, auth.RBACGlobal, resource); err != nil {
			return err
		}
	}
	return ctx.Err()
}
