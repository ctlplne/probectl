// SPDX-License-Identifier: LicenseRef-probectl-TBD

package topology

import (
	"encoding/json"
	"io"
	"strings"
)

type subjectRecord struct {
	Kind string `json:"kind"`
	Node *Node  `json:"node,omitempty"`
	Edge *Edge  `json:"edge,omitempty"`
}

// ExportSubject writes subject-matching topology nodes/edges for one tenant as
// JSONL. The topology store is a bounded derived identity cache, not the source
// telemetry store; this export is therefore a best-effort graph label receipt.
func (s *MemoryStore) ExportSubject(tenant, subject string, w io.Writer) (nodes, edges, deviceNodes int64, err error) {
	g, ok := s.graphIfExists(tenant)
	if !ok {
		return 0, 0, 0, nil
	}
	return g.ExportSubject(subject, w)
}

// DeleteSubject removes subject-matching derived topology labels for one
// tenant. Edges connected to deleted subject nodes are removed too, because they
// can otherwise preserve the identifier through graph structure.
func (s *MemoryStore) DeleteSubject(tenant, subject string) (deleted, remaining, deviceDeleted, deviceRemaining int64) {
	g, ok := s.graphIfExists(tenant)
	if !ok {
		return 0, 0, 0, 0
	}
	return g.DeleteSubject(subject)
}

func (s *IndexedStore) ExportSubject(tenant, subject string, w io.Writer) (nodes, edges, deviceNodes int64, err error) {
	g, ok := s.graphIfExists(tenant)
	if !ok {
		return 0, 0, 0, nil
	}
	return g.inner.ExportSubject(subject, w)
}

func (s *IndexedStore) DeleteSubject(tenant, subject string) (deleted, remaining, deviceDeleted, deviceRemaining int64) {
	g, ok := s.graphIfExists(tenant)
	if !ok {
		return 0, 0, 0, 0
	}
	deleted, remaining, deviceDeleted, deviceRemaining = g.inner.DeleteSubject(subject)
	if deleted > 0 {
		g.rebuildIndexes()
	}
	return deleted, remaining, deviceDeleted, deviceRemaining
}

// ExportSubject writes matching graph records as JSONL.
func (g *Graph) ExportSubject(subject string, w io.Writer) (nodes, edges, deviceNodes int64, err error) {
	subject = strings.ToLower(strings.TrimSpace(subject))
	if subject == "" {
		return 0, 0, 0, nil
	}
	g.mu.RLock()
	defer g.mu.RUnlock()
	enc := json.NewEncoder(w)
	for _, n := range g.nodes {
		if !nodeMatchesSubject(n, subject) {
			continue
		}
		cp := *n
		if err := enc.Encode(subjectRecord{Kind: "node", Node: &cp}); err != nil {
			return nodes, edges, deviceNodes, err
		}
		nodes++
		if n.Kind == NodeDevice {
			deviceNodes++
		}
	}
	for _, e := range g.edges {
		if !edgeMatchesSubject(e, subject) {
			continue
		}
		cp := *e
		if err := enc.Encode(subjectRecord{Kind: "edge", Edge: &cp}); err != nil {
			return nodes, edges, deviceNodes, err
		}
		edges++
	}
	return nodes, edges, deviceNodes, nil
}

// DeleteSubject removes matching graph records. It returns total matching
// records deleted/remaining, plus the device-node subset for device receipts.
func (g *Graph) DeleteSubject(subject string) (deleted, remaining, deviceDeleted, deviceRemaining int64) {
	subject = strings.ToLower(strings.TrimSpace(subject))
	if subject == "" {
		return 0, 0, 0, 0
	}
	g.mu.Lock()
	defer g.mu.Unlock()

	deletedNodes := map[string]bool{}
	for id, n := range g.nodes {
		if !nodeMatchesSubject(n, subject) {
			continue
		}
		deleted++
		if n.Kind == NodeDevice {
			deviceDeleted++
		}
		deletedNodes[id] = true
		delete(g.nodes, id)
	}
	for id, e := range g.edges {
		if deletedNodes[e.From] || deletedNodes[e.To] || edgeMatchesSubject(e, subject) {
			deleted++
			delete(g.edges, id)
		}
	}
	for _, n := range g.nodes {
		if nodeMatchesSubject(n, subject) {
			remaining++
			if n.Kind == NodeDevice {
				deviceRemaining++
			}
		}
	}
	for _, e := range g.edges {
		if edgeMatchesSubject(e, subject) {
			remaining++
		}
	}
	if len(g.recent) > 0 {
		kept := g.recent[:0]
		for _, e := range g.recent {
			if _, ok := g.edges[e.ID]; ok {
				kept = append(kept, e)
			}
		}
		g.recent = kept
	}
	return deleted, remaining, deviceDeleted, deviceRemaining
}

func nodeMatchesSubject(n *Node, subject string) bool {
	if n == nil {
		return false
	}
	if subjectTextContains(subject, n.ID, n.Label, string(n.Kind)) {
		return true
	}
	return attrsMatchSubject(n.Attributes, subject)
}

func edgeMatchesSubject(e *Edge, subject string) bool {
	if e == nil {
		return false
	}
	if subjectTextContains(subject, e.ID, e.From, e.To, e.Label, string(e.Kind)) {
		return true
	}
	return attrsMatchSubject(e.Attributes, subject)
}

func attrsMatchSubject(attrs map[string]string, subject string) bool {
	for k, v := range attrs {
		if subjectTextContains(subject, k, v) {
			return true
		}
	}
	return false
}

func subjectTextContains(subject string, values ...string) bool {
	for _, v := range values {
		if strings.Contains(strings.ToLower(v), subject) {
			return true
		}
	}
	return false
}
