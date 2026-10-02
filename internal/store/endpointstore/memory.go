// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package endpointstore

import (
	"context"
	"encoding/json"
	"io"
	"sort"
	"strings"
	"sync"
	"time"
)

// Memory is the bounded-environment/lightweight implementation. Production
// profiles reject it through the existing volatile-store posture check.
type Memory struct {
	mu     sync.RWMutex
	events map[string][]Event
}

// NewMemory creates an empty memory store.
func NewMemory() *Memory { return &Memory{events: map[string][]Event{}} }

// Insert appends validated tenant-scoped events.
func (m *Memory) Insert(_ context.Context, events []Event) error {
	if err := validate(events); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, event := range events {
		m.events[event.TenantID] = append(m.events[event.TenantID], cloneEvent(event))
	}
	return nil
}

// Latest returns the newest event per (agent,type,signal-key) for one tenant.
func (m *Memory) Latest(_ context.Context, tenantID string) ([]Event, error) {
	if tenantID == "" {
		return nil, ErrNoTenant
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	latest := map[string]Event{}
	for _, event := range m.events[tenantID] {
		key := event.AgentID + "\x00" + event.Type + "\x00" + event.SignalKey
		if previous, ok := latest[key]; !ok || event.ObservedAt.After(previous.ObservedAt) {
			latest[key] = cloneEvent(event)
		}
	}
	out := make([]Event, 0, len(latest))
	for _, event := range latest {
		out = append(out, event)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ObservedAt.Before(out[j].ObservedAt) })
	return out, nil
}

// PruneTenantBefore removes old raw events from one tenant partition.
func (m *Memory) PruneTenantBefore(_ context.Context, tenantID string, cutoff time.Time) (int, error) {
	if tenantID == "" {
		return 0, ErrNoTenant
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	kept := m.events[tenantID][:0]
	deleted := 0
	for _, event := range m.events[tenantID] {
		if event.ObservedAt.Before(cutoff) {
			deleted++
			continue
		}
		kept = append(kept, event)
	}
	if len(kept) == 0 {
		delete(m.events, tenantID)
	} else {
		m.events[tenantID] = kept
	}
	return deleted, nil
}

// DeleteTenant deletes and verifies one tenant partition.
func (m *Memory) DeleteTenant(_ context.Context, tenantID string) (int64, error) {
	if tenantID == "" {
		return 0, ErrNoTenant
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.events, tenantID)
	return int64(len(m.events[tenantID])), nil
}

// DeleteSubject erases one tenant's durable events about the subject and
// verifies the same tenant+subject predicate then reads zero (ING-15). The
// per-replica read cache is a derived view; this durable delete is what keeps
// the subject from reappearing on the next Latest/restart across every replica.
func (m *Memory) DeleteSubject(_ context.Context, tenantID, subject string) (deleted, remaining int64, err error) {
	if tenantID == "" {
		return 0, -1, ErrNoTenant
	}
	subject = strings.TrimSpace(subject)
	if subject == "" {
		return 0, 0, nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	events := m.events[tenantID]
	kept := events[:0]
	for _, event := range events {
		if eventMatchesSubject(event, subject) {
			deleted++
			continue
		}
		kept = append(kept, event)
	}
	if len(kept) == 0 {
		delete(m.events, tenantID)
	} else {
		m.events[tenantID] = kept
	}
	for _, event := range m.events[tenantID] {
		if eventMatchesSubject(event, subject) {
			remaining++
		}
	}
	return deleted, remaining, nil
}

// ExportSubject writes one tenant's durable events about the subject as JSONL.
func (m *Memory) ExportSubject(_ context.Context, tenantID, subject string, w io.Writer) (int64, error) {
	if tenantID == "" {
		return 0, ErrNoTenant
	}
	subject = strings.TrimSpace(subject)
	if subject == "" {
		return 0, nil
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	enc := json.NewEncoder(w)
	var rows int64
	for i := range m.events[tenantID] {
		if !eventMatchesSubject(m.events[tenantID][i], subject) {
			continue
		}
		if err := enc.Encode(m.events[tenantID][i]); err != nil {
			return rows, err
		}
		rows++
	}
	return rows, nil
}

// eventMatchesSubject reports whether a durable event is about the subject by
// EXACT, field-typed equality (TEN-05): agent_id, target and signal_key are
// structured identifiers, and only attribute VALUES (not keys, which are column
// names) are compared. signal_type and error are not subject-bearing. A
// substring match here would let "10.0.0.1" erase "10.0.0.10"/"110.0.0.1".
func eventMatchesSubject(e Event, subject string) bool {
	if strings.EqualFold(e.AgentID, subject) ||
		strings.EqualFold(e.Target, subject) ||
		strings.EqualFold(e.SignalKey, subject) {
		return true
	}
	for _, v := range e.Attributes {
		if strings.EqualFold(v, subject) {
			return true
		}
	}
	return false
}

// ExportTenant writes only the requested tenant's raw event history as JSONL.
func (m *Memory) ExportTenant(_ context.Context, tenantID string, w io.Writer) (int64, error) {
	if tenantID == "" {
		return 0, ErrNoTenant
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	enc := json.NewEncoder(w)
	for i := range m.events[tenantID] {
		if err := enc.Encode(m.events[tenantID][i]); err != nil {
			return int64(i), err
		}
	}
	return int64(len(m.events[tenantID])), nil
}

// Close is a no-op for memory storage.
func (*Memory) Close() error { return nil }

func cloneEvent(event Event) Event {
	event.Metrics = cloneMap(event.Metrics)
	event.Attributes = cloneMap(event.Attributes)
	return event
}

func cloneMap[K comparable, V any](in map[K]V) map[K]V {
	if in == nil {
		return nil
	}
	out := make(map[K]V, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}
