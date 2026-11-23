// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"context"
	"slices"
	"strings"
	"time"

	"github.com/ctlplne/probectl/internal/entity"
	agentv1 "github.com/ctlplne/probectl/internal/gen/probectl/agent/v1"
)

type KubernetesTopologyObject struct {
	KubernetesObjectIdentity
	ID         string
	ObservedAt time.Time
}

type KubernetesTopologyLink struct {
	From, To   string
	Kind       agentv1.KubernetesInventoryRelationshipKind
	ObservedAt time.Time
}

type KubernetesTopologyProjection struct {
	entity.Scope
	Objects []KubernetesTopologyObject
	Links   []KubernetesTopologyLink
}

type kubernetesTopologyWitness struct {
	SourceID, GenerationID, Serial, UID string
	Kind                                agentv1.KubernetesInventoryKind
}

func (fact KubernetesInventoryFact) topologyWitness(kind agentv1.KubernetesInventoryKind, uid string) kubernetesTopologyWitness {
	return kubernetesTopologyWitness{SourceID: fact.SourceID, GenerationID: fact.GenerationID, Serial: fact.Serial, UID: uid, Kind: kind}
}

// TopologyProjection keeps original ownership edges and proven Service
// backends as separate metadata links. Both endpoint objects and the actual
// edge witness must be visible at the same instant in the same generation.
func (snapshot KubernetesInventorySnapshot) TopologyProjection(ctx context.Context, memoryBytes int64) (KubernetesTopologyProjection, error) {
	budget := roleInputAdmission{memory: memoryBytes, work: memoryBytes / 1024}
	scope, sources, err := snapshot.projectionSources(ctx, &budget)
	if err != nil {
		return KubernetesTopologyProjection{}, kubernetesInventoryReadError(err)
	}
	witnesses, visible, err := snapshot.topologyObjects(ctx, scope, sources, &budget)
	if err != nil {
		return KubernetesTopologyProjection{}, kubernetesInventoryReadError(err)
	}
	out := KubernetesTopologyProjection{Scope: scope}
	for _, object := range visible {
		out.Objects = append(out.Objects, object)
	}
	slices.SortFunc(out.Objects, func(a, b KubernetesTopologyObject) int { return strings.Compare(a.ID, b.ID) })

	links := make(map[KubernetesTopologyLink]bool)
	controllers := make(map[string]string)
	conflictingControllers := make(map[string]bool)
	for _, fact := range snapshot.Facts {
		if fact.Relationship == 0 {
			continue
		}
		if err := budget.charge(ctx, 1024, 1); err != nil {
			return KubernetesTopologyProjection{}, kubernetesInventoryReadError(err)
		}
		if link, found := topologyLinkFromInventory(fact, witnesses, visible); found {
			if link.Kind == kubernetesController {
				if parent, exists := controllers[link.From]; exists && parent != link.To {
					conflictingControllers[link.From] = true
				}
				controllers[link.From] = link.To
			}
			links[link] = true
		}
	}
	for link := range links {
		if link.Kind != kubernetesController || !conflictingControllers[link.From] {
			out.Links = append(out.Links, link)
		}
	}
	slices.SortFunc(out.Links, func(a, b KubernetesTopologyLink) int {
		if order := strings.Compare(a.From, b.From); order != 0 {
			return order
		}
		if order := strings.Compare(a.To, b.To); order != 0 {
			return order
		}
		if a.Kind != b.Kind {
			return int(a.Kind - b.Kind)
		}
		return a.ObservedAt.Compare(b.ObservedAt)
	})
	return out, ctx.Err()
}

func (snapshot KubernetesInventorySnapshot) topologyObjects(ctx context.Context, scope entity.Scope,
	sources map[string]KubernetesInventorySource, budget *roleInputAdmission) (
	map[kubernetesTopologyWitness]KubernetesTopologyObject, map[string]KubernetesTopologyObject, error) {
	witnesses := make(map[kubernetesTopologyWitness]KubernetesTopologyObject)
	visible := make(map[string]KubernetesTopologyObject)
	conflicts := make(map[string]bool)
	for _, fact := range snapshot.Facts {
		if !fact.validWithinSources(sources) || fact.ProjectionAt == nil ||
			fact.ProjectionAt.Before(fact.From) || !fact.ProjectionAt.Before(fact.Until) {
			return nil, nil, ErrKubernetesInventoryAuthority
		}
		if err := budget.charge(ctx, 1024, 1); err != nil {
			return nil, nil, err
		}
		if fact.Name == "" {
			continue
		}
		source := sources[fact.SourceID]
		key := fact.topologyWitness(fact.WitnessKind, fact.WitnessUID)
		object := KubernetesTopologyObject{
			KubernetesObjectIdentity: KubernetesObjectIdentity{ClusterID: source.ClusterID, Namespace: source.Namespace,
				UID: fact.WitnessUID, Name: fact.Name, Kind: fact.WitnessKind},
			ID:         "kubernetes:" + scope.ContextID + "/" + source.ClusterID + "/" + source.Namespace + "/" + fact.WitnessUID,
			ObservedAt: fact.ProjectionAt.UTC(),
		}
		if _, exists := witnesses[key]; exists {
			return nil, nil, ErrKubernetesInventoryAuthority
		}
		witnesses[key] = object
		if fact.WitnessKind == kubernetesSlice || conflicts[object.ID] {
			continue
		}
		previous, exists := visible[object.ID]
		if exists && previous.KubernetesObjectIdentity != object.KubernetesObjectIdentity {
			conflicts[object.ID] = true
			delete(visible, object.ID)
		} else if !exists || object.ObservedAt.After(previous.ObservedAt) {
			visible[object.ID] = object
		}
	}
	return witnesses, visible, nil
}

func topologyLinkFromInventory(fact KubernetesInventoryFact, witnesses map[kubernetesTopologyWitness]KubernetesTopologyObject,
	visible map[string]KubernetesTopologyObject) (KubernetesTopologyLink, bool) {
	if fact.Relationship != kubernetesController && fact.Relationship != kubernetesBackend {
		return KubernetesTopologyLink{}, false
	}
	original := witnesses[fact.topologyWitness(fact.WitnessKind, fact.WitnessUID)]
	from := witnesses[fact.topologyWitness(fact.FromKind, fact.FromUID)]
	to := witnesses[fact.topologyWitness(fact.ToKind, fact.ToUID)]
	if original.ID == "" || from.ID == "" || to.ID == "" || from.ID == to.ID ||
		!original.ObservedAt.Equal(*fact.ProjectionAt) ||
		!from.ObservedAt.Equal(original.ObservedAt) || !to.ObservedAt.Equal(original.ObservedAt) {
		return KubernetesTopologyLink{}, false
	}
	if visible[from.ID].KubernetesObjectIdentity != from.KubernetesObjectIdentity ||
		visible[to.ID].KubernetesObjectIdentity != to.KubernetesObjectIdentity {
		return KubernetesTopologyLink{}, false
	}
	return KubernetesTopologyLink{From: from.ID, To: to.ID, Kind: fact.Relationship, ObservedAt: original.ObservedAt}, true
}
