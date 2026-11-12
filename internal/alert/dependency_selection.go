// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package alert

import (
	"context"
	"errors"
	"sort"
	"time"

	"github.com/ctlplne/probectl/internal/tenancy"
)

// ErrDependencyEvidence refuses incomplete, stale or unadmitted hold authority.
var ErrDependencyEvidence = errors.New("alert: complete current dependency evidence is unavailable")

// These are operation-local evidence, not caller-supplied authorization. The
// adapter must resolve canonical registry parents in a tenant storage scope,
// capture current sources and recheck that authority before publication.
type dependencyVertex struct {
	EntityID   string
	Parents    []string
	FreshUntil time.Time
}

type dependencyCause struct {
	TenantID, ContextID, EntityID, IncidentID string
	ObservedAt, FreshUntil                    time.Time
}

type dependencySnapshot struct {
	TenantID, ContextID string
	At                  time.Time
	Complete            bool
	Vertices            []dependencyVertex
	Causes              []dependencyCause
}

type dependencySelection struct {
	Held   bool
	At     time.Time
	Causes []dependencyCause
	Reason string
}

// Resource admission is separate from graph size or path depth. Charge before
// allocation and return no partial causes on an incomplete or refused graph.
type dependencyBudget struct{ memory, work int64 }

func (b *dependencyBudget) charge(memory, work int64) error {
	if memory < 0 || work < 0 || memory > b.memory || work > b.work {
		return ErrDependencyEvidence
	}
	b.memory -= memory
	b.work -= work
	return nil
}

// selectDependencyHold finds a complete cut of currently failed ancestors.
// A healthy alternative path means ordinary delivery; a graph cycle, missing
// source or stale parent is unknown evidence and cannot justify suppression.
// Independent symptoms are never made dependent merely by physical adjacency.
func selectDependencyHold(ctx context.Context, graph dependencySnapshot, target string, reachabilitySymptom bool, budget dependencyBudget) (dependencySelection, error) {
	if err := ctx.Err(); err != nil {
		return dependencySelection{}, err
	}
	tenant, ok := tenancy.FromContext(ctx)
	if !ok || tenant.String() != graph.TenantID || !canonicalQueryID(graph.TenantID) || !canonicalQueryID(graph.ContextID) {
		return dependencySelection{}, tenancy.ErrNoTenant
	}
	if !graph.Complete || graph.At.IsZero() || !canonicalQueryID(target) || len(graph.Vertices) == 0 {
		return dependencySelection{}, ErrDependencyEvidence
	}
	if err := budget.charge(4096, 4096); err != nil {
		return dependencySelection{}, err
	}
	nodes := make(map[string]dependencyVertex)
	children := make(map[string][]string)
	remaining := make(map[string]int)
	for _, vertex := range graph.Vertices {
		if err := ctx.Err(); err != nil {
			return dependencySelection{}, err
		}
		if !canonicalQueryID(vertex.EntityID) || !vertex.FreshUntil.After(graph.At) {
			return dependencySelection{}, ErrDependencyEvidence
		}
		if _, exists := nodes[vertex.EntityID]; exists {
			return dependencySelection{}, ErrDependencyEvidence
		}
		if err := budget.charge(512, 512); err != nil {
			return dependencySelection{}, err
		}
		nodes[vertex.EntityID] = vertex
		remaining[vertex.EntityID] = len(vertex.Parents)
		parents := make(map[string]bool)
		for _, parent := range vertex.Parents {
			if err := budget.charge(256, 256); err != nil {
				return dependencySelection{}, err
			}
			if !canonicalQueryID(parent) || parents[parent] || parent == vertex.EntityID {
				return dependencySelection{}, ErrDependencyEvidence
			}
			parents[parent] = true
			children[parent] = append(children[parent], vertex.EntityID)
		}
	}
	if _, exists := nodes[target]; !exists {
		return dependencySelection{}, ErrDependencyEvidence
	}
	for parent := range children {
		if _, exists := nodes[parent]; !exists {
			return dependencySelection{}, ErrDependencyEvidence
		}
	}
	// Topological validation is iterative: a legitimate deep chain must not
	// overflow the call stack, and cycles must not be mistaken for blocked paths.
	queue := make([]string, 0)
	for id, count := range remaining {
		if count == 0 {
			queue = append(queue, id)
		}
	}
	visited := 0
	for len(queue) > 0 {
		if err := ctx.Err(); err != nil {
			return dependencySelection{}, err
		}
		id := queue[0]
		queue = queue[1:]
		visited++
		for _, child := range children[id] {
			remaining[child]--
			if remaining[child] == 0 {
				queue = append(queue, child)
			}
		}
	}
	if visited != len(nodes) {
		return dependencySelection{}, ErrDependencyEvidence
	}
	causes := make(map[string]dependencyCause)
	for _, cause := range graph.Causes {
		if err := budget.charge(512, 512); err != nil {
			return dependencySelection{}, err
		}
		if cause.TenantID != graph.TenantID || cause.ContextID != graph.ContextID || !canonicalQueryID(cause.IncidentID) || cause.ObservedAt.IsZero() || cause.ObservedAt.After(graph.At) || !cause.FreshUntil.After(graph.At) {
			return dependencySelection{}, ErrDependencyEvidence
		}
		if _, exists := nodes[cause.EntityID]; !exists {
			return dependencySelection{}, ErrDependencyEvidence
		}
		if _, duplicate := causes[cause.EntityID]; duplicate {
			return dependencySelection{}, ErrDependencyEvidence
		}
		causes[cause.EntityID] = cause
	}
	out := dependencySelection{At: graph.At}
	if !reachabilitySymptom {
		out.Reason = "the symptom is independent of upstream reachability"
		return out, nil
	}
	queue = append(queue, target)
	seen := make(map[string]bool)
	for len(queue) > 0 {
		if err := ctx.Err(); err != nil {
			return dependencySelection{}, err
		}
		id := queue[0]
		queue = queue[1:]
		if seen[id] {
			continue
		}
		seen[id] = true
		if cause, down := causes[id]; down && id != target {
			out.Causes = append(out.Causes, cause)
			continue
		}
		vertex := nodes[id]
		if len(vertex.Parents) == 0 {
			return dependencySelection{At: graph.At, Reason: "a current upstream path remains independent of the failed elements"}, nil
		}
		queue = append(queue, vertex.Parents...)
	}
	if len(out.Causes) == 0 {
		return dependencySelection{}, ErrDependencyEvidence
	}
	sort.Slice(out.Causes, func(i, j int) bool { return out.Causes[i].EntityID < out.Causes[j].EntityID })
	out.Held = true
	out.Reason = "current upstream failures cover every observed dependency path"
	return out, nil
}
