// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flowstore

import (
	"context"
	"encoding/json"
	"io"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/ctlplne/probectl/internal/govern"
)

const (
	defaultCounterTenantMemoryBytes int64 = 1 << 30
	defaultCounterTotalMemoryBytes  int64 = 4 << 30
)

type counterMemoryTenant struct {
	rows  map[string]CounterRow
	bytes int64
}
type counterMemoryState struct {
	tenants                        map[string]*counterMemoryTenant
	bytes, tenantLimit, totalLimit int64
}

func (m *Memory) counterStateLocked() *counterMemoryState {
	if m.counters.tenants == nil {
		m.counters.tenants = map[string]*counterMemoryTenant{}
	}
	if m.counters.tenantLimit == 0 {
		m.counters.tenantLimit = defaultCounterTenantMemoryBytes
		m.counters.totalLimit = defaultCounterTotalMemoryBytes
	}
	return &m.counters
}

// WithCounterMemoryBudget sets retained byte admission, independently of flow
// FIFO settings. Counter polls never evict another poll or tenant to fit.
func (m *Memory) WithCounterMemoryBudget(tenantBytes, totalBytes int64) error {
	if m == nil || tenantBytes <= 0 || totalBytes < tenantBytes {
		return ErrCounterHistoryInput
	}
	m.counterMu.Lock()
	defer m.counterMu.Unlock()
	state := m.counterStateLocked()
	if state.bytes > totalBytes {
		return ErrCounterHistoryBudget
	}
	for _, tenant := range state.tenants {
		if tenant.bytes > tenantBytes {
			return ErrCounterHistoryBudget
		}
	}
	state.tenantLimit, state.totalLimit = tenantBytes, totalBytes
	return nil
}

func (m *Memory) InsertCounterPoll(ctx context.Context, rows []CounterRow, budget CounterBudget) error {
	if err := validateCounterPoll(ctx, rows, budget); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, budget.Timeout)
	defer cancel()
	m.counterMu.Lock()
	defer m.counterMu.Unlock()
	state := m.counterStateLocked()
	key := rows[0].TenantID
	tenant := state.tenants[key]
	if tenant == nil {
		tenant = &counterMemoryTenant{rows: map[string]CounterRow{}}
	}
	var added int64
	for _, row := range rows {
		if err := ctx.Err(); err != nil {
			return err
		}
		if previous, ok := tenant.rows[counterRowID(row)]; ok {
			if counterDocument(previous) != counterDocument(row) {
				return ErrCounterHistoryInput
			}
			continue
		}
		charge := counterRowCharge(row)
		if charge <= 0 || charge > state.tenantLimit-tenant.bytes-added || charge > state.totalLimit-state.bytes-added {
			return ErrCounterHistoryBudget
		}
		added += charge
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	// Admission completed for every point before the first map mutation.
	for _, row := range rows {
		tenant.rows[counterRowID(row)] = row
	}
	tenant.bytes += added
	state.bytes += added
	state.tenants[key] = tenant
	return nil
}

func sortCounterRows(rows []CounterRow) {
	sort.Slice(rows, func(i, j int) bool {
		a, b := rows[i], rows[j]
		if a.ContextID != b.ContextID {
			return a.ContextID < b.ContextID
		}
		if a.DeviceID != b.DeviceID {
			return a.DeviceID < b.DeviceID
		}
		if a.IfIndex != b.IfIndex {
			return a.IfIndex < b.IfIndex
		}
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		if !a.PollStartedAt.Equal(b.PollStartedAt) {
			return a.PollStartedAt.Before(b.PollStartedAt)
		}
		return counterRowID(a) < counterRowID(b)
	})
}

func (m *Memory) CounterPoints(ctx context.Context, query CounterQuery) ([]CounterRow, error) {
	if err := validateCounterQuery(ctx, query); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, query.Budget.Timeout)
	defer cancel()
	contains := compileCounterSelection(query)
	rows, err := func() ([]CounterRow, error) {
		m.counterMu.Lock()
		defer m.counterMu.Unlock()
		state := m.counterStateLocked()
		tenant := state.tenants[query.TenantID]
		if tenant == nil {
			return []CounterRow{}, nil
		}
		remaining, work := query.Budget.MemoryBytes/2, query.Budget.WorkUnits
		var out []CounterRow
		for _, row := range tenant.rows {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			charge := counterRowCharge(row)
			if charge <= 0 || charge > work {
				return nil, ErrCounterHistoryBudget
			}
			work -= charge
			if !contains(row) {
				continue
			}
			if charge > remaining {
				return nil, ErrCounterHistoryBudget
			}
			remaining -= charge
			out = append(out, row)
		}
		return out, nil
	}()
	if err != nil {
		return nil, err
	}
	sortCounterRows(rows)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return rows, nil
}

func (m *Memory) WalkCounterPoints(ctx context.Context, query CounterQuery, visit func(CounterRow) error) error {
	if visit == nil {
		return ErrCounterHistoryInput
	}
	ctx, cancel := context.WithTimeout(ctx, query.Budget.Timeout)
	defer cancel()
	rows, err := m.CounterPoints(ctx, query)
	if err != nil {
		return err
	}
	for _, row := range rows {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := visit(row); err != nil {
			return err
		}
	}
	return nil
}

type counterSubjectMatch struct {
	literal         string
	address, source *regexp.Regexp
}

func newCounterSubjectMatch(subject string) (counterSubjectMatch, error) {
	if subject == "" || strings.TrimSpace(subject) != subject || !utf8.ValidString(subject) {
		return counterSubjectMatch{}, ErrCounterHistoryInput
	}
	out := counterSubjectMatch{literal: subject}
	if source, ok := govern.SubjectNetworkPattern(subject); ok {
		address, _ := govern.SubjectNetworkExactPattern(subject)
		var err error
		out.address, err = regexp.Compile(address)
		if err != nil {
			return counterSubjectMatch{}, ErrCounterHistoryInput
		}
		out.source, err = regexp.Compile(source)
		if err != nil {
			return counterSubjectMatch{}, ErrCounterHistoryInput
		}
	}
	return out, nil
}
func (m counterSubjectMatch) matches(row CounterRow) bool {
	if m.address != nil {
		return m.address.MatchString(row.AgentID) || m.source.MatchString(row.SourceRef)
	}
	return strings.ToLower(row.AgentID) == strings.ToLower(m.literal) || strings.ToLower(row.SourceRef) == strings.ToLower(m.literal)
}

func matchCounterSubjects(subjects []string) (func(CounterRow) bool, error) {
	if len(subjects) == 0 {
		return nil, ErrCounterHistoryInput
	}
	matchers := make([]counterSubjectMatch, len(subjects))
	for i, subject := range subjects {
		matcher, err := newCounterSubjectMatch(subject)
		if err != nil {
			return nil, err
		}
		matchers[i] = matcher
	}
	return func(row CounterRow) bool {
		for _, matcher := range matchers {
			if matcher.matches(row) {
				return true
			}
		}
		return false
	}, nil
}

func (m *Memory) DeleteCounterTenant(ctx context.Context, tenant string) (int64, error) {
	if err := validateCounterTenant(ctx, tenant); err != nil {
		return -1, err
	}
	m.counterMu.Lock()
	defer m.counterMu.Unlock()
	state := m.counterStateLocked()
	if own := state.tenants[tenant]; own != nil {
		state.bytes -= own.bytes
		delete(state.tenants, tenant)
	}
	return 0, nil
}

func (m *Memory) DeleteCounterSubject(ctx context.Context, tenant, subject string) (int64, int64, error) {
	return m.DeleteCounterSubjects(ctx, tenant, []string{subject})
}

func (m *Memory) DeleteCounterSubjects(ctx context.Context, tenant string, subjects []string) (int64, int64, error) {
	if err := validateCounterTenant(ctx, tenant); err != nil {
		return 0, -1, err
	}
	match, err := matchCounterSubjects(subjects)
	if err != nil {
		return 0, -1, err
	}
	return m.deleteCounterRows(ctx, tenant, match)
}

func (m *Memory) deleteCounterRows(ctx context.Context, tenant string, match func(CounterRow) bool) (int64, int64, error) {
	m.counterMu.Lock()
	defer m.counterMu.Unlock()
	state := m.counterStateLocked()
	own := state.tenants[tenant]
	if own == nil {
		return 0, 0, nil
	}
	var keys []string
	for key, row := range own.rows {
		if err := ctx.Err(); err != nil {
			return 0, -1, err
		}
		if match(row) {
			keys = append(keys, key)
		}
	}
	if err := ctx.Err(); err != nil {
		return 0, -1, err
	}
	for _, key := range keys {
		charge := counterRowCharge(own.rows[key])
		delete(own.rows, key)
		own.bytes -= charge
		state.bytes -= charge
	}
	if len(own.rows) == 0 {
		delete(state.tenants, tenant)
	}
	return int64(len(keys)), 0, nil
}

func (m *Memory) DeleteCountersBefore(ctx context.Context, tenant string, cutoff time.Time) error {
	if err := validateCounterTenant(ctx, tenant); err != nil {
		return err
	}
	if !counterClock(cutoff) {
		return ErrCounterHistoryInput
	}
	_, _, err := m.deleteCounterRows(ctx, tenant, func(row CounterRow) bool { return row.PollStartedAt.Before(cutoff) })
	return err
}

func (m *Memory) ExportCounterTenant(ctx context.Context, tenant string, w io.Writer) (int64, error) {
	return m.exportCounters(ctx, tenant, nil, w)
}
func (m *Memory) ExportCounterSubject(ctx context.Context, tenant, subject string, w io.Writer) (int64, error) {
	return m.ExportCounterSubjects(ctx, tenant, []string{subject}, w)
}
func (m *Memory) ExportCounterSubjects(ctx context.Context, tenant string, subjects []string, w io.Writer) (int64, error) {
	if len(subjects) == 0 {
		return 0, ErrCounterHistoryInput
	}
	return m.exportCounters(ctx, tenant, subjects, w)
}
func (m *Memory) exportCounters(ctx context.Context, tenant string, subjects []string, w io.Writer) (int64, error) {
	if err := validateCounterTenant(ctx, tenant); err != nil {
		return 0, err
	}
	if w == nil {
		return 0, ErrCounterHistoryInput
	}
	var match func(CounterRow) bool
	var err error
	if len(subjects) > 0 {
		match, err = matchCounterSubjects(subjects)
		if err != nil {
			return 0, err
		}
	}
	rows, err := func() ([]CounterRow, error) {
		m.counterMu.Lock()
		defer m.counterMu.Unlock()
		state := m.counterStateLocked()
		own := state.tenants[tenant]
		if own == nil {
			return []CounterRow{}, nil
		}
		var out []CounterRow
		for _, row := range own.rows {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			if match == nil || match(row) {
				out = append(out, row)
			}
		}
		return out, nil
	}()
	if err != nil {
		return 0, err
	}
	sortCounterRows(rows)
	encoder := json.NewEncoder(w)
	for i, row := range rows {
		if err := ctx.Err(); err != nil {
			return int64(i), err
		}
		if err := encoder.Encode(counterPortableDocument(row)); err != nil {
			return int64(i), err
		}
	}
	return int64(len(rows)), nil
}
