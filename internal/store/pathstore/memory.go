// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package pathstore

import (
	"context"
	"sync"
	"time"

	"github.com/ctlplne/probectl/internal/path"
)

// Memory is an in-process Store that retains saved paths for query (lightweight
// mode and tests).
type Memory struct {
	mu    sync.Mutex
	saved map[string][]Snapshot // tenant_id -> immutable discovery rounds
}

// NewMemory returns an in-memory path store.
func NewMemory() *Memory { return &Memory{saved: map[string][]Snapshot{}} }

// Save retains a copy of the path under its tenant.
func (m *Memory) Save(_ context.Context, tenantID string, p *path.Path) error {
	if tenantID == "" {
		return ErrNoTenant
	}
	id, err := randomID()
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.saved[tenantID] = append(m.saved[tenantID], Snapshot{
		ID: id, ObservedAt: time.Now().UTC(), Path: clonePath(p),
	})
	return nil
}

// DeleteTenant removes every saved path for the tenant (S-T5 verifiable
// erasure, U-027) and returns how many were removed and how many remain.
func (m *Memory) DeleteTenant(_ context.Context, tenantID string) (deleted, remaining int, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	deleted = len(m.saved[tenantID])
	delete(m.saved, tenantID)
	return deleted, 0, nil
}

// Latest returns the most recently saved path to target for the tenant.
func (m *Memory) Latest(_ context.Context, tenantID, target string) (*path.Path, bool, error) {
	if tenantID == "" {
		return nil, false, ErrNoTenant
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	rounds := m.saved[tenantID]
	for i := len(rounds) - 1; i >= 0; i-- {
		if rounds[i].Path.Target == target {
			p := clonePath(&rounds[i].Path)
			return &p, true, nil
		}
	}
	return nil, false, nil
}

// History returns newest-first rounds from only the requested tenant+target.
func (m *Memory) History(_ context.Context, tenantID, target string, q HistoryQuery) ([]Snapshot, error) {
	if tenantID == "" {
		return nil, ErrNoTenant
	}
	limit := historyLimit(q.Limit)
	requested := make(map[string]bool, len(q.IDs))
	for _, id := range q.IDs {
		requested[id] = true
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	rounds := m.saved[tenantID]
	out := make([]Snapshot, 0, min(limit, len(rounds)))
	for i := len(rounds) - 1; i >= 0 && len(out) < limit; i-- {
		round := rounds[i]
		if round.Path.Target != target {
			continue
		}
		if len(requested) > 0 {
			if !requested[round.ID] {
				continue
			}
		} else if (!q.From.IsZero() && round.ObservedAt.Before(q.From)) ||
			(!q.To.IsZero() && round.ObservedAt.After(q.To)) {
			continue
		}
		round.Path = clonePath(&round.Path)
		out = append(out, round)
	}
	return out, nil
}

// Close is a no-op.
func (m *Memory) Close() error { return nil }

// ForTenant returns the paths saved for a tenant (test/lightweight query).
func (m *Memory) ForTenant(tenantID string) []*path.Path {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]*path.Path, 0, len(m.saved[tenantID]))
	for i := range m.saved[tenantID] {
		p := clonePath(&m.saved[tenantID][i].Path)
		out = append(out, &p)
	}
	return out
}

func clonePath(in *path.Path) path.Path {
	if in == nil {
		return path.Path{}
	}
	out := *in
	if in.MeasurementFidelity != nil {
		fidelity := *in.MeasurementFidelity
		out.MeasurementFidelity = &fidelity
	}
	out.Hops = make([]path.Hop, len(in.Hops))
	for i := range in.Hops {
		out.Hops[i] = in.Hops[i]
		out.Hops[i].Nodes = make([]path.HopNode, len(in.Hops[i].Nodes))
		for j := range in.Hops[i].Nodes {
			out.Hops[i].Nodes[j] = in.Hops[i].Nodes[j]
			out.Hops[i].Nodes[j].MPLS = append([]path.MPLSLabel(nil), in.Hops[i].Nodes[j].MPLS...)
		}
	}
	out.Links = append([]path.Link(nil), in.Links...)
	return out
}

func historyLimit(limit int) int {
	if limit <= 0 || limit > 100 {
		return 50
	}
	return limit
}
