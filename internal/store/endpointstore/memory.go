// SPDX-License-Identifier: LicenseRef-probectl-TBD

package endpointstore

import (
	"context"
	"encoding/json"
	"io"
	"sort"
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
