// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package alert

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"time"

	"github.com/ctlplne/probectl/internal/tenancy"
)

// ErrDependencyEvidence refuses incomplete, stale or unadmitted hold authority.
var ErrDependencyEvidence = errors.New("alert: complete current dependency evidence is unavailable")
var ErrDependencyBudget = fmt.Errorf("%w: operation resource admission refused", ErrDependencyEvidence)

// These are operation-local evidence, not caller-supplied authorization. The
// adapter must resolve canonical registry parents in a tenant storage scope,
// capture current sources and recheck that authority before publication.
type DependencyVertex struct {
	EntityID   string
	Parents    []string
	FreshUntil time.Time
}

type DependencyCause struct {
	TenantID, ContextID, EntityID, IncidentID string
	ObservedAt, FreshUntil                    time.Time
}

type DependencySnapshot struct {
	TenantID, ContextID string
	At                  time.Time
	Complete            bool
	Vertices            []DependencyVertex
	Causes              []DependencyCause
}

type dependencyVertex = DependencyVertex
type dependencyCause = DependencyCause
type dependencySnapshot = DependencySnapshot

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
		return ErrDependencyBudget
	}
	b.memory -= memory
	b.work -= work
	return nil
}

// preparedDependencyGraph owns an immutable, current operation snapshot. Cuts
// are computed in topological order once, rather than walking every ancestor
// again for every firing series. Output size still consumes shared admission.
type preparedDependencyGraph struct {
	tenant, contextID string
	at, until         time.Time
	nodes             map[string]dependencyVertex
	causes            map[string]dependencyCause
	cuts              map[string][]dependencyCause
	budget            dependencyBudget
}

func prepareDependencyGraph(ctx context.Context, graph dependencySnapshot, budget dependencyBudget) (*preparedDependencyGraph, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	tenant, ok := tenancy.FromContext(ctx)
	if !ok || tenant.String() != graph.TenantID || !canonicalQueryID(graph.TenantID) || !canonicalQueryID(graph.ContextID) {
		return nil, tenancy.ErrNoTenant
	}
	if !graph.Complete || graph.At.IsZero() || len(graph.Vertices) == 0 {
		return nil, ErrDependencyEvidence
	}
	if err := budget.charge(4096, 4096); err != nil {
		return nil, err
	}
	p := &preparedDependencyGraph{tenant: graph.TenantID, contextID: graph.ContextID, at: graph.At,
		nodes: map[string]dependencyVertex{}, causes: map[string]dependencyCause{}, cuts: map[string][]dependencyCause{}, budget: budget}
	children, remaining, err := p.indexVertices(ctx, graph.Vertices)
	if err != nil {
		return nil, err
	}
	if err := p.indexCauses(ctx, graph.Causes); err != nil {
		return nil, err
	}
	if err := p.buildCuts(ctx, children, remaining); err != nil {
		return nil, err
	}
	return p, nil
}

func (p *preparedDependencyGraph) indexVertices(ctx context.Context, vertices []dependencyVertex) (map[string][]string, map[string]int, error) {
	children := map[string][]string{}
	remaining := map[string]int{}
	for _, v := range vertices {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		if !canonicalQueryID(v.EntityID) || !v.FreshUntil.After(p.at) {
			return nil, nil, ErrDependencyEvidence
		}
		if _, exists := p.nodes[v.EntityID]; exists {
			return nil, nil, ErrDependencyEvidence
		}
		if err := p.budget.charge(768, 768); err != nil {
			return nil, nil, err
		}
		parents := map[string]bool{}
		for _, parent := range v.Parents {
			if err := p.budget.charge(256, 256); err != nil {
				return nil, nil, err
			}
			if !canonicalQueryID(parent) || parents[parent] || parent == v.EntityID {
				return nil, nil, ErrDependencyEvidence
			}
			parents[parent] = true
			children[parent] = append(children[parent], v.EntityID)
		}
		v.Parents = slices.Clone(v.Parents)
		p.nodes[v.EntityID] = v
		remaining[v.EntityID] = len(v.Parents)
		if p.until.IsZero() || v.FreshUntil.Before(p.until) {
			p.until = v.FreshUntil
		}
	}
	for parent := range children {
		if _, exists := p.nodes[parent]; !exists {
			return nil, nil, ErrDependencyEvidence
		}
	}
	return children, remaining, nil
}

func (p *preparedDependencyGraph) indexCauses(ctx context.Context, causes []dependencyCause) error {
	for _, cause := range causes {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := p.budget.charge(512, 512); err != nil {
			return err
		}
		if cause.TenantID != p.tenant || cause.ContextID != p.contextID || !canonicalQueryID(cause.IncidentID) || cause.ObservedAt.IsZero() || cause.ObservedAt.After(p.at) || !cause.FreshUntil.After(p.at) {
			return ErrDependencyEvidence
		}
		if _, exists := p.nodes[cause.EntityID]; !exists {
			return ErrDependencyEvidence
		}
		if _, exists := p.causes[cause.EntityID]; exists {
			return ErrDependencyEvidence
		}
		p.causes[cause.EntityID] = cause
		p.until = minDependencyTime(p.until, cause.FreshUntil)
	}
	return nil
}

func (p *preparedDependencyGraph) buildCuts(ctx context.Context, children map[string][]string, remaining map[string]int) error {
	queue := make([]string, 0, len(p.nodes))
	for id, count := range remaining {
		if count == 0 {
			queue = append(queue, id)
		}
	}
	for index := 0; index < len(queue); index++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		id := queue[index]
		cut, err := p.parentCut(ctx, p.nodes[id].Parents)
		if err != nil {
			return err
		}
		p.cuts[id] = cut
		for _, child := range children[id] {
			remaining[child]--
			if remaining[child] == 0 {
				queue = append(queue, child)
			}
		}
	}
	if len(queue) != len(p.nodes) {
		return ErrDependencyEvidence
	}
	return nil
}

func (p *preparedDependencyGraph) parentCut(ctx context.Context, parents []string) ([]dependencyCause, error) {
	if len(parents) == 0 {
		return nil, nil
	}
	selected := map[string]dependencyCause{}
	for _, parent := range parents {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		var causes []dependencyCause
		if own, down := p.causes[parent]; down {
			causes = []dependencyCause{own}
		} else {
			causes = p.cuts[parent]
		}
		if len(causes) == 0 {
			return nil, nil
		} // a current independent root path
		for _, cause := range causes {
			if err := p.budget.charge(0, 256); err != nil {
				return nil, err
			}
			if _, exists := selected[cause.EntityID]; !exists {
				if err := p.budget.charge(512, 0); err != nil {
					return nil, err
				}
				selected[cause.EntityID] = cause
			}
		}
	}
	cut := make([]dependencyCause, 0, len(selected))
	for _, cause := range selected {
		cut = append(cut, cause)
	}
	sort.Slice(cut, func(i, j int) bool { return cut[i].EntityID < cut[j].EntityID })
	return cut, nil
}

func (p *preparedDependencyGraph) selectHold(ctx context.Context, target string, reachability bool) (dependencySelection, error) {
	if err := ctx.Err(); err != nil {
		return dependencySelection{}, err
	}
	tenant, ok := tenancy.FromContext(ctx)
	if !ok || tenant.String() != p.tenant {
		return dependencySelection{}, tenancy.ErrNoTenant
	}
	if _, exists := p.nodes[target]; !exists {
		return dependencySelection{}, ErrDependencyEvidence
	}
	out := dependencySelection{At: p.at, Reason: "the symptom is independent of upstream reachability"}
	if !reachability {
		return out, nil
	}
	causes := p.cuts[target]
	if len(causes) == 0 {
		out.Reason = "a current upstream path remains independent of the failed elements"
		return out, nil
	}
	if err := p.budget.charge(int64(len(causes))*512, int64(len(causes))*256); err != nil {
		return dependencySelection{}, err
	}
	out.Held = true
	out.Reason = "current upstream failures cover every observed dependency path"
	out.Causes = slices.Clone(causes)
	return out, nil
}
