// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flowstore

import (
	"context"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/store/chclient"
)

// SnapshotInputs is a server-authored, encrypted cache-validity receipt, never
// user grammar. It contains no predicate literals, saved expressions or tenant
// selector. OldestInput includes all contributing groups, including Other.
type SnapshotInputs struct {
	Version        int       `json:"version"`
	From           time.Time `json:"from"`
	To             time.Time `json:"to"`
	OldestInput    time.Time `json:"oldest_input,omitempty"`
	Source         string    `json:"source"`
	DataSeries     string    `json:"dataseries"`
	BucketSeconds  int       `json:"bucket_seconds"`
	Fields         []string  `json:"fields"`
	NeedsComplete  bool      `json:"needs_complete"`
	CompleteInputs bool      `json:"complete_inputs"`
	TagLookup      bool      `json:"tag_lookup,omitempty"`
	TagSubjects    []string  `json:"tag_subjects,omitempty"`
	Empty          bool      `json:"empty"`
}

var ErrSnapshotInputs = errors.New("flow snapshot input coverage is invalid or no longer available")

// SnapshotInputsForTenant uses the same validated tenant vocabulary as the
// executed plan. Unbound/foreign dynamic fields never become source coverage.
func SnapshotInputsForTenant(ctx context.Context, tenant string, result PlanResult) (SnapshotInputs, error) {
	if err := ctx.Err(); err != nil {
		return SnapshotInputs{}, err
	}
	if tenant == "" {
		return SnapshotInputs{}, ErrNoTenant
	}
	vocabulary, _, err := flow.QueryVocabularyFromContext(ctx, tenant)
	if err != nil {
		return SnapshotInputs{}, ErrTagQueryScope
	}
	return snapshotInputsFor(result, vocabulary)
}

func snapshotInputsFor(result PlanResult, vocabulary flow.QueryVocabulary) (SnapshotInputs, error) {
	plan, err := flow.NormalizeQueryPlanWithVocabulary(result.Query, time.Now(), vocabulary)
	if err != nil {
		return SnapshotInputs{}, ErrSnapshotInputs
	}
	fields := append(slices.Clone(plan.GroupBy), plan.MatrixWith...)
	fields = append(fields, flow.QueryFilterFields(plan.Filter)...)
	fields = append(fields, planDistinctFields(plan)...)
	tagLookup := false
	var tagSubjects []string
	for i, name := range fields {
		field, ok := vocabulary.Lookup(name)
		if !ok {
			return SnapshotInputs{}, ErrSnapshotInputs
		}
		if field.Derived == "tenant_tag" {
			// Current tags join by exporter and require complete inputs;
			// preserve their expiry even for an hour-aligned window.
			fields[i], tagLookup = "exporter", true
			if kind, _, qualified := strings.Cut(field.TagKey, "."); qualified {
				if kind == "in_interface" || kind == "out_interface" {
					kind = "interface"
				}
				tagSubjects = append(tagSubjects, kind)
			}
			if field.Column != "" {
				fields = append(fields, field.Column)
			}
		}
	}
	slices.Sort(fields)
	fields = slices.Compact(fields)
	slices.Sort(tagSubjects)
	tagSubjects = slices.Compact(tagSubjects)
	complete := result.Source == "raw"
	if result.Coverage != nil {
		complete = result.Coverage.CompleteInputs
	}
	clock := SnapshotInputs{Version: 2, From: plan.From, To: plan.To, OldestInput: result.OldestInput.UTC(), Source: result.Source, DataSeries: plan.DataSeries, BucketSeconds: plan.BucketSeconds, Fields: fields, Empty: result.TotalGroups == 0, TagLookup: tagLookup, CompleteInputs: complete, TagSubjects: tagSubjects}
	clock.NeedsComplete = clock.needsComplete()
	if err := clock.validate(); err != nil {
		return SnapshotInputs{}, err
	}
	return clock, nil
}

func (c SnapshotInputs) needsComplete() bool {
	if c.TagLookup {
		return true
	}
	if c.BucketSeconds%3600 != 0 || !c.From.Equal(c.From.Truncate(time.Hour)) || !c.To.Equal(c.To.Truncate(time.Hour)) {
		return true
	}
	for _, name := range c.Fields {
		field, ok := flow.LookupQueryField(name)
		if !ok || !field.LegacyHourly {
			return true
		}
	}
	return false
}

func (c SnapshotInputs) validate() error {
	if c.Version != 2 || !c.From.Before(c.To) || c.BucketSeconds < flow.MinPlanBucketSeconds || c.BucketSeconds > flow.MaxPlanBucketSeconds || len(c.Fields) > len(flow.QueryFields()) {
		return ErrSnapshotInputs
	}
	if c.Source != "raw" && c.Source != "rollup" {
		return ErrSnapshotInputs
	}
	if (c.Source == "raw" || c.NeedsComplete) && !c.CompleteInputs {
		return ErrSnapshotInputs
	}
	if c.TagLookup && !slices.Contains(c.Fields, "exporter") {
		return ErrSnapshotInputs
	}
	if len(c.TagSubjects) > 3 || len(c.TagSubjects) > 0 && !c.TagLookup {
		return ErrSnapshotInputs
	}
	previousSubject := ""
	for _, kind := range c.TagSubjects {
		if kind <= previousSubject || kind != "agent" && kind != "device" && kind != "interface" {
			return ErrSnapshotInputs
		}
		previousSubject = kind
	}
	if c.DataSeries != "auto" && c.DataSeries != "raw" && c.DataSeries != "rollup" {
		return ErrSnapshotInputs
	}
	if c.DataSeries != "auto" && c.DataSeries != c.Source {
		return ErrSnapshotInputs
	}
	if c.Empty != c.OldestInput.IsZero() {
		return ErrSnapshotInputs
	}
	if !c.Empty && (c.OldestInput.Before(c.From) || !c.OldestInput.Before(c.To)) {
		return ErrSnapshotInputs
	}
	if c.NeedsComplete != c.needsComplete() {
		return ErrSnapshotInputs
	}
	previous := ""
	for _, name := range c.Fields {
		if _, ok := flow.LookupQueryField(name); !ok || name <= previous {
			return ErrSnapshotInputs
		}
		previous = name
	}
	return nil
}

// ExpiresAt returns the first configured INPUT expiry, not a query-window cap.
// Zero means the requested information has no finite input clock. The cache
// still has its own short lifetime. Deployment0 is the existing explicit
// keep-forever choice; a legacy tenant0 inherits, as the retention sweep does.
// Tenant policy expiry uses original event time; exact retained COLUMN TTL
// uses the immutable hour bucket. Raw table TTL truncates to whole seconds.
func (c SnapshotInputs) ExpiresAt(deploymentDays int, tenantDays *int) (time.Time, error) {
	if err := c.validate(); err != nil {
		return time.Time{}, err
	}
	if deploymentDays < 0 || tenantDays != nil && *tenantDays < 0 {
		return time.Time{}, ErrSnapshotInputs
	}
	if c.Empty || c.Source == "rollup" && !c.NeedsComplete {
		return time.Time{}, nil
	}
	var expiry time.Time
	include := func(at time.Time, days int) {
		if days <= 0 {
			return
		}
		candidate := at.UTC().AddDate(0, 0, days)
		if expiry.IsZero() || candidate.Before(expiry) {
			expiry = candidate
		}
	}
	if c.Source == "raw" {
		include(c.OldestInput.Truncate(time.Second), deploymentDays)
	} else {
		include(c.OldestInput.Truncate(time.Hour), deploymentDays)
	}
	if tenantDays != nil {
		include(c.OldestInput, *tenantDays)
	}
	if !expiry.IsZero() && !expiry.After(c.OldestInput) {
		return time.Time{}, ErrSnapshotInputs
	}
	return expiry, nil
}

// SnapshotInputVerifier checks the current tenant-scoped source policy without
// recalculating row ranking or statistics against later ingestion.
type SnapshotInputVerifier interface {
	VerifySnapshotInputs(context.Context, string, SnapshotInputs) error
}

func SnapshotInputVerifierOf(store Store) (SnapshotInputVerifier, bool) {
	for {
		switch current := store.(type) {
		case *writeFencedStore:
			store = current.next
		case *subjectDeletingWriteFencedStore:
			store = current.next
		default:
			result, ok := store.(SnapshotInputVerifier)
			return result, ok
		}
	}
}

func (m *Memory) VerifySnapshotInputs(_ context.Context, tenant string, clock SnapshotInputs) error {
	if strings.TrimSpace(tenant) == "" {
		return ErrNoTenant
	}
	if err := clock.validate(); err != nil {
		return err
	}
	if clock.Source != "raw" || clock.DataSeries == "rollup" {
		return ErrSnapshotInputs
	}
	return nil
}

func (c *ClickHouse) VerifySnapshotInputs(ctx context.Context, tenant string, clock SnapshotInputs) error {
	if strings.TrimSpace(tenant) == "" {
		return ErrNoTenant
	}
	if err := clock.validate(); err != nil {
		return err
	}
	budget := ExplorerQueryBudget(c)
	if err := budget.Validate(); err != nil {
		return err
	}
	ctx = withExplorerBudget(ctx, budget)
	ctx, cancel := context.WithTimeout(ctx, budget.ExecutionLimit)
	defer cancel()
	target, err := c.route(ctx, tenant)
	if err != nil {
		return err
	}
	lane, err := c.readLane(target, tenant)
	if err != nil {
		return err
	}
	if !lane.Reader {
		return chclient.ErrReaderRequired
	}
	if clock.Empty {
		return nil
	}
	// This is only a coverage probe, not executable public grammar. GroupBy
	// carries up to36 required field names so legacy availability checks include
	// filter/distinct dependencies without storing the expression or its values.
	plan := flow.QueryPlan{From: clock.From, To: clock.To, GroupBy: slices.Clone(clock.Fields), BucketSeconds: clock.BucketSeconds, DataSeries: clock.DataSeries}
	source, err := c.planSourceFor(ctx, target, lane, tenant, plan)
	if err != nil {
		return err
	}
	if clock.DataSeries == "raw" && source.kind != "raw" || source.coverage != nil && !source.coverage.CompleteInputs && clock.NeedsComplete {
		return ErrSnapshotInputs
	}
	return nil
}
