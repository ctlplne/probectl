// SPDX-License-Identifier: LicenseRef-probectl-TBD

package ebpfstore

import (
	"context"
	"encoding/json"
	"io"
	"strings"
)

// ExportSubject writes one tenant's subject-matching eBPF service-edge
// aggregates as JSONL. eBPF rows are aggregates, but their workload labels are
// addressable enough for a bounded subject receipt.
func (m *Memory) ExportSubject(_ context.Context, tenantID, subject string, w io.Writer) (int64, error) {
	subject = strings.ToLower(strings.TrimSpace(subject))
	if tenantID == "" || subject == "" {
		return 0, nil
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	enc := json.NewEncoder(w)
	var rows int64
	for _, e := range m.tenants[tenantID] {
		if !edgeMatchesSubject(*e, subject) {
			continue
		}
		if err := enc.Encode(e); err != nil {
			return rows, err
		}
		rows++
	}
	return rows, nil
}

// DeleteSubject removes subject-matching eBPF service-edge aggregates for one
// tenant and returns the matching count that remains after deletion.
func (m *Memory) DeleteSubject(_ context.Context, tenantID, subject string) (deleted, remaining int64, err error) {
	subject = strings.ToLower(strings.TrimSpace(subject))
	if tenantID == "" || subject == "" {
		return 0, 0, nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	part := m.tenants[tenantID]
	for key, e := range part {
		if edgeMatchesSubject(*e, subject) {
			delete(part, key)
			deleted++
		}
	}
	for _, e := range part {
		if edgeMatchesSubject(*e, subject) {
			remaining++
		}
	}
	if len(part) == 0 {
		delete(m.tenants, tenantID)
	}
	return deleted, remaining, nil
}

func edgeMatchesSubject(e Edge, subject string) bool {
	for _, v := range []string{e.AgentID, e.SrcWorkload, e.DstWorkload, e.L7Protocol} {
		if strings.Contains(strings.ToLower(v), subject) {
			return true
		}
	}
	return false
}
