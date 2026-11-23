// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"context"
	"net/netip"
	"slices"
	"time"

	"github.com/ctlplne/probectl/internal/entity"
	agentv1 "github.com/ctlplne/probectl/internal/gen/probectl/agent/v1"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type KubernetesObjectIdentity struct {
	ClusterID, Namespace, UID, Name string
	Kind                            agentv1.KubernetesInventoryKind
}

type KubernetesAddressSpan struct {
	Address     netip.Addr
	From, Until time.Time
	Owner       KubernetesObjectIdentity
}

type KubernetesAddressProjection struct {
	entity.Scope
	Spans     []KubernetesAddressSpan
	workloads []KubernetesAddressSpan
}

// Resolve matches a caller-admitted half-open event range against one
// continuous span, including the caller's clock uncertainty in that range.
func (projection KubernetesAddressProjection) Resolve(address netip.Addr, from, until time.Time) (KubernetesObjectIdentity, bool) {
	return resolveKubernetesAddress(projection.Spans, address, from, until)
}

// ResolveWorkload requires both the Pod and its controller chain to cover
// the interval. The address timeline alone carries no controller identity.
func (projection KubernetesAddressProjection) ResolveWorkload(address netip.Addr, from, until time.Time) (KubernetesObjectIdentity, bool) {
	if pod, ok := projection.Resolve(address, from, until); !ok || pod.Kind != kubernetesPod {
		return KubernetesObjectIdentity{}, false
	}
	return resolveKubernetesAddress(projection.workloads, address, from, until)
}

func resolveKubernetesAddress(spans []KubernetesAddressSpan, address netip.Addr, from, until time.Time) (KubernetesObjectIdentity, bool) {
	if !address.IsValid() || address.Zone() != "" || from.IsZero() || !until.After(from) {
		return KubernetesObjectIdentity{}, false
	}
	address = address.Unmap()
	index, exact := slices.BinarySearchFunc(spans, from, func(span KubernetesAddressSpan, from time.Time) int {
		if order := span.Address.Compare(address); order != 0 {
			return order
		}
		return span.From.Compare(from)
	})
	if !exact {
		index--
	}
	if index < 0 {
		return KubernetesObjectIdentity{}, false
	}
	span := spans[index]
	if span.Address != address || span.Until.Before(until) || span.Owner.UID == "" {
		return KubernetesObjectIdentity{}, false
	}
	return span.Owner, true
}

type kubernetesInventoryObjectKey struct {
	SourceID, GenerationID, UID string
	Kind                        agentv1.KubernetesInventoryKind
}

func (fact KubernetesInventoryFact) witnessedObject() kubernetesInventoryObjectKey {
	return kubernetesInventoryObjectKey{
		SourceID: fact.SourceID, GenerationID: fact.GenerationID,
		UID: fact.WitnessUID, Kind: fact.WitnessKind,
	}
}

type kubernetesAddressChange struct {
	At    time.Time
	Owner KubernetesObjectIdentity
	Delta int
}

// AddressProjection reduces the complete, already authorized inventory
// population for one routing context to disjoint half-open owner spans. The
// flow exporter may know its routing context without knowing the cluster. An
// overlap with another cluster or namespace therefore counts as a conflict.
// A Service VIP belongs to the Service itself, and Pod IPs retain Pod identity
// independently of any EndpointSlice membership or workload owner.
func (snapshot KubernetesInventorySnapshot) AddressProjection(ctx context.Context, memoryBytes int64) (KubernetesAddressProjection, error) {
	budget := roleInputAdmission{memory: memoryBytes, work: memoryBytes / 1024}
	scope, sources, err := snapshot.projectionSources(ctx, &budget)
	if err != nil {
		return KubernetesAddressProjection{}, kubernetesInventoryReadError(err)
	}
	changes, workloads, err := kubernetesAddressChanges(ctx, sources, snapshot.Facts, &budget)
	if err != nil {
		return KubernetesAddressProjection{}, kubernetesInventoryReadError(err)
	}
	addresses := make([]netip.Addr, 0, len(changes))
	for address := range changes {
		addresses = append(addresses, address)
	}
	slices.SortFunc(addresses, netip.Addr.Compare)
	out := KubernetesAddressProjection{Scope: scope}
	for _, address := range addresses {
		if err := ctx.Err(); err != nil {
			return KubernetesAddressProjection{}, err
		}
		out.Spans = appendKubernetesAddressSpans(out.Spans, address, changes[address])
		out.workloads = appendKubernetesAddressSpans(out.workloads, address, workloads[address])
	}
	return out, ctx.Err()
}

func (snapshot KubernetesInventorySnapshot) projectionSources(ctx context.Context,
	budget *roleInputAdmission) (entity.Scope, map[string]KubernetesInventorySource, error) {
	scope, err := snapshot.Scope.Normalize()
	tenant, bound := tenancy.FromContext(ctx)
	if err != nil || !bound || tenant.String() != scope.TenantID {
		return entity.Scope{}, nil, ErrKubernetesInventoryAuthority
	}
	if err := budget.charge(ctx, 4096, 1); err != nil {
		return entity.Scope{}, nil, err
	}
	if int64(len(snapshot.Sources)) > budget.memory/1024 {
		return entity.Scope{}, nil, ErrKubernetesInventoryBudget
	}
	sources := make(map[string]KubernetesInventorySource, len(snapshot.Sources))
	for _, source := range snapshot.Sources {
		if source.ContextID != scope.ContextID || !canonicalKubernetesUploadID(source.ID) ||
			!canonicalKubernetesUploadID(source.ClusterID) || !kubernetesInventoryNamespace.MatchString(source.Namespace) ||
			source.ClosedAt != nil || sources[source.ID].ID != "" {
			return entity.Scope{}, nil, ErrKubernetesInventoryAuthority
		}
		if err := budget.charge(ctx, 1024, 1); err != nil {
			return entity.Scope{}, nil, err
		}
		sources[source.ID] = source
	}
	return scope, sources, nil
}

func kubernetesAddressChanges(ctx context.Context, sources map[string]KubernetesInventorySource,
	facts []KubernetesInventoryFact, budget *roleInputAdmission) (map[netip.Addr][]kubernetesAddressChange, map[netip.Addr][]kubernetesAddressChange, error) {
	objects := make(map[kubernetesInventoryObjectKey]KubernetesInventoryFact)
	controllers := make(map[kubernetesInventoryObjectKey]KubernetesInventoryFact)
	conflicts := make(map[kubernetesInventoryObjectKey]bool)
	for _, fact := range facts {
		if !fact.validWithinSources(sources) {
			return nil, nil, ErrKubernetesInventoryAuthority
		}
		if err := budget.charge(ctx, 1024, 1); err != nil {
			return nil, nil, err
		}
		if fact.Name != "" {
			key := fact.witnessedObject()
			if _, exists := objects[key]; exists {
				return nil, nil, ErrKubernetesInventoryAuthority
			}
			objects[key] = fact
		}
		if fact.Relationship == kubernetesController {
			key := fact.witnessedObject()
			if _, exists := controllers[key]; exists {
				conflicts[key] = true
			}
			controllers[key] = fact
		}
	}
	changes := make(map[netip.Addr][]kubernetesAddressChange)
	workloads := make(map[netip.Addr][]kubernetesAddressChange)
	for _, fact := range facts {
		if fact.Address == "" {
			continue
		}
		addr, err := netip.ParseAddr(fact.Address)
		object, exists := objects[fact.witnessedObject()]
		if err != nil || addr.Zone() != "" || addr.Is4In6() || !addr.IsGlobalUnicast() ||
			!exists || !sameKubernetesWindow(object, fact) ||
			fact.WitnessKind != kubernetesPod && fact.WitnessKind != kubernetesService {
			return nil, nil, ErrKubernetesInventoryAuthority
		}
		if err := budget.charge(ctx, 2048, 1); err != nil {
			return nil, nil, err
		}
		source := sources[fact.SourceID]
		owner := KubernetesObjectIdentity{
			ClusterID: source.ClusterID, Namespace: source.Namespace, Kind: fact.WitnessKind,
			UID: fact.WitnessUID, Name: object.Name,
		}
		changes[addr] = appendKubernetesAddressChanges(changes[addr], fact.From, fact.Until, owner)
		if fact.WitnessKind == kubernetesPod {
			if err := budget.charge(ctx, 3072, 3); err != nil {
				return nil, nil, err
			}
			workload, from, until := kubernetesWorkloadOwner(object, owner, objects, controllers, conflicts)
			workloads[addr] = appendKubernetesWorkloadChanges(workloads[addr], fact, workload, from, until)
		}
	}
	return changes, workloads, nil
}

func sameKubernetesWindow(a, b KubernetesInventoryFact) bool {
	return a.WindowIndex == b.WindowIndex && a.Serial == b.Serial && a.From.Equal(b.From) && a.Until.Equal(b.Until)
}

func kubernetesWorkloadOwner(pod KubernetesInventoryFact, identity KubernetesObjectIdentity,
	objects, controllers map[kubernetesInventoryObjectKey]KubernetesInventoryFact, conflicts map[kubernetesInventoryObjectKey]bool) (KubernetesObjectIdentity, time.Time, time.Time) {
	key, from, until := pod.witnessedObject(), pod.From, pod.Until
	current := pod
	for range 3 {
		edge, owned := controllers[key]
		if conflicts[key] {
			break
		}
		if !owned {
			if current.ControllerUnowned && key.Kind > kubernetesSlice {
				identity.UID, identity.Name, identity.Kind = current.WitnessUID, current.Name, current.WitnessKind
				return identity, from, until
			}
			break
		}
		if current.ControllerUnowned || !sameKubernetesWindow(current, edge) ||
			edge.FromKind != key.Kind || edge.FromUID != key.UID || !kubernetesWorkloadParent(edge.FromKind, edge.ToKind) {
			break
		}
		key.Kind, key.UID = edge.ToKind, edge.ToUID
		parent, found := objects[key]
		if !found || parent.Serial != pod.Serial {
			break
		}
		if parent.From.After(from) {
			from = parent.From
		}
		if parent.Until.Before(until) {
			until = parent.Until
		}
		if !until.After(from) {
			break
		}
		current = parent
	}
	return KubernetesObjectIdentity{}, time.Time{}, time.Time{}
}

func kubernetesWorkloadParent(child, parent agentv1.KubernetesInventoryKind) bool {
	const (
		replicaSet = agentv1.KubernetesInventoryKind_KUBERNETES_INVENTORY_KIND_REPLICA_SET
		job        = agentv1.KubernetesInventoryKind_KUBERNETES_INVENTORY_KIND_JOB
		deployment = agentv1.KubernetesInventoryKind_KUBERNETES_INVENTORY_KIND_DEPLOYMENT
		cronJob    = agentv1.KubernetesInventoryKind_KUBERNETES_INVENTORY_KIND_CRON_JOB
	)
	switch child {
	case kubernetesPod:
		switch parent {
		case replicaSet, job, deployment,
			agentv1.KubernetesInventoryKind_KUBERNETES_INVENTORY_KIND_DAEMON_SET,
			agentv1.KubernetesInventoryKind_KUBERNETES_INVENTORY_KIND_STATEFUL_SET,
			agentv1.KubernetesInventoryKind_KUBERNETES_INVENTORY_KIND_REPLICATION_CONTROLLER:
			return true
		}
	case replicaSet:
		return parent == deployment
	case job:
		return parent == cronJob
	}
	return false
}

func appendKubernetesAddressChanges(changes []kubernetesAddressChange, from, until time.Time, owner KubernetesObjectIdentity) []kubernetesAddressChange {
	if !until.After(from) {
		return changes
	}
	return append(changes, kubernetesAddressChange{At: from, Owner: owner, Delta: 1}, kubernetesAddressChange{At: until, Owner: owner, Delta: -1})
}

func appendKubernetesWorkloadChanges(changes []kubernetesAddressChange, pod KubernetesInventoryFact, owner KubernetesObjectIdentity, from, until time.Time) []kubernetesAddressChange {
	unknown := KubernetesObjectIdentity{}
	if owner.UID == "" {
		return appendKubernetesAddressChanges(changes, pod.From, pod.Until, unknown)
	}
	changes = appendKubernetesAddressChanges(changes, pod.From, from, unknown)
	changes = appendKubernetesAddressChanges(changes, from, until, owner)
	return appendKubernetesAddressChanges(changes, until, pod.Until, unknown)
}

func (fact KubernetesInventoryFact) validWithinSources(sources map[string]KubernetesInventorySource) bool {
	source, found := sources[fact.SourceID]
	return found && fact.WitnessUID != "" && knownKubernetesInventoryKind(fact.WitnessKind) &&
		canonicalKubernetesUploadID(fact.GenerationID) && fact.WindowIndex >= 0 && !fact.From.IsZero() &&
		!fact.From.Before(source.AssignedAt) && fact.Until.After(fact.From)
}

func appendKubernetesAddressSpans(spans []KubernetesAddressSpan, address netip.Addr, changes []kubernetesAddressChange) []KubernetesAddressSpan {
	slices.SortFunc(changes, func(a, b kubernetesAddressChange) int { return a.At.Compare(b.At) })
	active := make(map[KubernetesObjectIdentity]int)
	for first := 0; first < len(changes); {
		start, next := changes[first].At, first
		// Apply simultaneous changes before examining uniqueness. A handoff
		// at one boundary never creates a positive-width shared claim.
		for ; next < len(changes) && changes[next].At.Equal(start); next++ {
			change := changes[next]
			active[change.Owner] += change.Delta
			if active[change.Owner] == 0 {
				delete(active, change.Owner)
			}
		}
		if len(active) == 1 && next < len(changes) {
			for owner := range active {
				spans = appendKubernetesAddressSpan(spans, address, start, changes[next].At, owner)
			}
		}
		first = next
	}
	return spans
}

func appendKubernetesAddressSpan(spans []KubernetesAddressSpan, address netip.Addr, from, until time.Time, owner KubernetesObjectIdentity) []KubernetesAddressSpan {
	if len(spans) != 0 {
		last := &spans[len(spans)-1]
		if last.Address == address && last.Until.Equal(from) && last.Owner == owner {
			last.Until = until
			return spans
		}
	}
	return append(spans, KubernetesAddressSpan{Address: address, From: from, Until: until, Owner: owner})
}
