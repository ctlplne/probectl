// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package pipeline

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// tenantRejected is a process-wide count of batches/records dropped by tenant
// verification across ALL bus-published planes (WIRE-001). Surfaced on
// /metrics so an operator can alert on cross-tenant injection attempts — the
// rejections are no longer only visible in the logs.
var tenantRejected atomic.Uint64

// TenantRejectedTotal reports the process-wide count of records dropped
// fail-closed by tenant verification (the tenant-isolation rejection counter,
// WIRE-001). Exposed as a /metrics gauge.
func TenantRejectedTotal() uint64 { return tenantRejected.Load() }

// noteTenantRejection bumps the process-wide tenant-rejection counter. Called
// by every consumer's reject path in addition to its own per-consumer counter.
func noteTenantRejection() { tenantRejected.Add(1) }

// TENANT-101 / WIRE-001: the bus-published planes (flow, device, eBPF,
// endpoint) used to trust the payload's tenant_id — whatever tenant the agent
// CONFIG claimed, the server stored. This file makes the server side
// authoritative:
//
//   - On a NAMESPACED lane (siloed/hybrid tenants), the lane itself names the
//     tenant: lanes are single-tenant by construction and broker ACLs bind a
//     tenant's credentials to its own namespace. The payload tenant is
//     OVERWRITTEN with the lane tenant; the claimed agent must additionally
//     be registered in that tenant.
//   - On a SHARED lane (pooled), the claimed (tenant, agent) pair must match
//     the agents registry — which was populated through the mTLS gRPC
//     registration where the tenant came from the certificate's SPIFFE
//     identity, never the request (F50). An unknown agent, a mismatched
//     pair, or a registry error REJECTS the batch (fail closed).
//
// The residual shared-lane gap — an attacker holding one tenant's bus
// credentials who knows another tenant's registered agent id could forge that
// pair on the shared lane — is closed in the default multi-tenant/regulated
// posture by STRICT-LANE mode (WIRE-001): the shared pooled lane is refused for
// agent-published planes, so the only authoritative path is a tenant-namespaced
// lane (single-tenant by construction + broker-ACL isolated), which a forged
// payload tenant_id cannot reach. Non-strict (single-tenant) deployments keep
// the registry check. A future per-record cryptographic identity (SVID-signed
// batches, the Sprint 11 enrollment work) would additionally let the SHARED
// lane be safe; until then strict-lane is the closure. All rejections increment
// a process-wide counter surfaced on /metrics (probectl_pipeline_tenant_rejected_total).

// Verification/rejection errors (fail closed — callers drop and count).
var (
	ErrTenantNotBound     = errors.New("pipeline: agent is not registered to the claimed tenant (fail closed)")
	ErrMixedBatch         = errors.New("pipeline: batch mixes tenant/agent identities (fail closed)")
	ErrNoTenant           = errors.New("pipeline: record carries no tenant id (fail closed)")
	ErrBindingUnavailable = errors.New("pipeline: tenant binding lookup unavailable (fail closed)")
	// ErrSharedLaneForbidden (WIRE-001): in strict-lane mode the shared
	// pooled lane is refused for agent-published collector planes — the only
	// authoritative path is a tenant-namespaced lane (single-tenant by
	// construction + broker-ACL isolated), which a payload tenant_id cannot
	// forge. Closes the residual shared-lane forgery surface in
	// multi-tenant/regulated deployments. Fail closed.
	ErrSharedLaneForbidden = errors.New("pipeline: shared pooled lane is forbidden for agent-published planes in strict-lane mode — publish on a tenant-namespaced lane (WIRE-001, fail closed)")
)

// TenantBinding answers "is this agent registered to this tenant?".
type TenantBinding interface {
	// Verify returns nil when agentID is registered in tenantID's registry
	// partition; ErrTenantNotBound when it is not; ErrBindingUnavailable on
	// lookup failure (callers treat both as a rejection).
	Verify(ctx context.Context, tenantID, agentID string) error
}

// RegistryBinding is the production TenantBinding: it looks the agent up in
// the claimed tenant's OWN registry partition (tenant-scoped, RLS-enforced —
// the lookup itself cannot cross tenants), with a small TTL cache so the hot
// path stays off Postgres.
type RegistryBinding struct {
	// versions remembers the last version recorded per (tenant, agent) so a
	// steady fleet costs no writes: only a change reaches the registry.
	versions map[bindingKey]string

	pool *pgxpool.Pool

	mu    sync.Mutex
	cache map[bindingKey]bindingEntry
	now   func() time.Time

	posTTL, negTTL time.Duration
	maxEntries     int
}

type bindingKey struct{ tenant, agent string }
type bindingEntry struct {
	bound   bool
	expires time.Time
}

// NewRegistryBinding builds the registry-backed binding. Defaults: positive
// results cached 60s, negative 10s (a just-registered agent becomes ingestable
// quickly), 65536 entries (full reset beyond — correctness never depends on
// the cache).
func NewRegistryBinding(pool *pgxpool.Pool) *RegistryBinding {
	return &RegistryBinding{
		pool: pool, cache: map[bindingKey]bindingEntry{}, now: time.Now,
		posTTL: 60 * time.Second, negTTL: 10 * time.Second, maxEntries: 65536,
	}
}

// RecordVersion implements VersionRecorder: a verified batch that names its
// producer's build version keeps agents.agent_version current (DPR-093). One
// write per change per replica; never an error for the caller.
func (b *RegistryBinding) RecordVersion(ctx context.Context, tenantID, agentID, version string) {
	if tenantID == "" || agentID == "" || version == "" {
		return
	}
	k := bindingKey{tenantID, agentID}
	b.mu.Lock()
	if b.versions == nil {
		b.versions = map[bindingKey]string{}
	}
	if b.versions[k] == version {
		b.mu.Unlock()
		return
	}
	if len(b.versions) >= b.maxEntries {
		b.versions = map[bindingKey]string{} // bounded like the binding cache
	}
	b.versions[k] = version
	b.mu.Unlock()
	err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenantID)), b.pool,
		func(ctx context.Context, sc tenancy.Scope) error {
			return (store.Agents{}).RecordVersion(ctx, sc, agentID, version)
		})
	if err != nil {
		// Forget the optimistic entry so the next verified batch retries.
		b.mu.Lock()
		delete(b.versions, k)
		b.mu.Unlock()
	}
}

// isUUID reports whether id is a canonical UUID, the shape every tenant and
// agent id has in the registry.
func isUUID(id string) bool {
	_, err := uuid.Parse(id)
	return err == nil
}

// Verify implements TenantBinding.
func (b *RegistryBinding) Verify(ctx context.Context, tenantID, agentID string) error {
	if tenantID == "" {
		return ErrNoTenant
	}
	if agentID == "" {
		return ErrTenantNotBound // an unattributable record is never authoritative
	}
	// DPR-114: agent and tenant ids are UUIDs in the registry, so an id that is
	// not one cannot be bound to anything — it is a rejection, not an outage.
	// Deciding that here also keeps a producer sending malformed ids from
	// driving one failing tenant transaction per batch against the database:
	// the lookup below only ever ran, and failed, because the cast happened in
	// Postgres. Both ids are checked; a malformed tenant id would fail the same
	// cast inside the tenant fence.
	if !isUUID(agentID) || !isUUID(tenantID) {
		return ErrTenantNotBound
	}
	k := bindingKey{tenantID, agentID}

	b.mu.Lock()
	if e, ok := b.cache[k]; ok && b.now().Before(e.expires) {
		b.mu.Unlock()
		if e.bound {
			return nil
		}
		return ErrTenantNotBound
	}
	b.mu.Unlock()

	bound := false
	err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenantID)), b.pool,
		func(ctx context.Context, sc tenancy.Scope) error {
			a, err := (store.Agents{}).Get(ctx, sc, agentID)
			if err != nil {
				return err
			}
			bound = a != nil
			if bound {
				// DPR-082: a verified batch IS the collector's heartbeat. This
				// runs once per positive-cache TTL (a minute) per agent, so the
				// fleet view can say "online" about a bus collector — and
				// "offline" when its batches stop — instead of freezing the
				// status at registration time. Best effort: liveness never
				// gates ingest.
				_, _ = (store.Agents{}).Heartbeat(ctx, sc, agentID)
			}
			return nil
		})
	if err != nil {
		// Lookup failure ≠ "not bound", but both REJECT: fail closed. The
		// distinction is what an operator acts on — "unavailable" sends them to
		// the database — so only a real lookup failure can reach here (DPR-114).
		return fmt.Errorf("%w: %v", ErrBindingUnavailable, err)
	}

	b.mu.Lock()
	if len(b.cache) >= b.maxEntries {
		b.cache = map[bindingKey]bindingEntry{} // bounded: reset, never grow
	}
	ttl := b.negTTL
	if bound {
		ttl = b.posTTL
	}
	b.cache[k] = bindingEntry{bound: bound, expires: b.now().Add(ttl)}
	b.mu.Unlock()

	if !bound {
		return ErrTenantNotBound
	}
	return nil
}

// laneSub is one bus subscription: a topic plus the tenant the lane is bound
// to ("" = the shared, pooled lane).
type laneSub struct{ topic, group, laneTenant string }

// Identity is one record's claimed (tenant, agent) pair.
// Identity is one record's (tenant, agent) claim. Version is the producing
// agent's build version when the batch envelope carries one (DPR-093): the
// lane copies it onto every record's identity so a batch stays homogeneous,
// and a verified batch records it against the fleet entry.
type Identity struct{ Tenant, Agent, Version string }

// VersionRecorder is the optional side of a TenantBinding that keeps the fleet
// view's agent_version current from what verified batches report (DPR-093).
// Bus collectors never carried a version at registration; their batches are
// the only truthful source, and the staged fleet rollout verifies against it.
type VersionRecorder interface {
	RecordVersion(ctx context.Context, tenantID, agentID, version string)
}

// recordVersion forwards a verified batch's version to the binding when it
// can record one. Best effort: a failed stamp never gates ingest.
func recordVersion(ctx context.Context, binding TenantBinding, tenantID, agentID, version string) {
	if version == "" || binding == nil {
		return
	}
	if r, ok := binding.(VersionRecorder); ok {
		r.RecordVersion(ctx, tenantID, agentID, version)
	}
}

// VerifyBatchTenant decides the AUTHORITATIVE tenant for a batch, or rejects
// it. ids must be the (tenant, agent) of every record in the batch —
// heterogeneous batches are rejected outright (a mixed batch is itself an
// injection vector). laneTenant is non-empty when the message arrived on a
// tenant-namespaced lane. binding == nil skips registry verification (unit
// tests without a DB; production always installs one).
//
// Returns the tenant every record must be re-stamped with before persistence,
// and overwritten=true when the payload disagreed with the lane (counted by
// callers — visible, never silent).
func VerifyBatchTenant(ctx context.Context, binding TenantBinding, laneTenant string, ids []Identity) (authoritative string, overwritten bool, err error) {
	return VerifyBatchTenantStrict(ctx, binding, laneTenant, false, ids)
}

// VerifyBatchTenantStrict is VerifyBatchTenant with the WIRE-001 strict-lane
// option. When strict is true and the batch arrives on the SHARED pooled lane
// (laneTenant == ""), the batch is REJECTED with ErrSharedLaneForbidden: in
// strict mode the only authoritative path for an agent-published collector
// plane is a tenant-namespaced lane, where the lane (broker-ACL isolated,
// single-tenant by construction) names the tenant and a forged payload
// tenant_id cannot be honored. On a namespaced lane strict has no effect (the
// lane is already authoritative). strict=false preserves the prior behavior
// (registry-verified shared lane), so non-strict/single-tenant deployments are
// unchanged.
func VerifyBatchTenantStrict(ctx context.Context, binding TenantBinding, laneTenant string, strict bool, ids []Identity) (authoritative string, overwritten bool, err error) {
	if len(ids) == 0 {
		return "", false, ErrNoTenant
	}
	first := ids[0]
	for _, id := range ids[1:] {
		if id != first {
			return "", false, ErrMixedBatch
		}
	}
	if first.Tenant == "" {
		return "", false, ErrNoTenant
	}

	if laneTenant != "" {
		// Namespaced lane: the lane IS the tenant. Payload disagreement is
		// overwritten (and surfaced); the agent must still be registered in
		// the lane's tenant.
		overwritten = first.Tenant != laneTenant
		if binding != nil {
			if err := binding.Verify(ctx, laneTenant, first.Agent); err != nil {
				return "", false, err
			}
			recordVersion(ctx, binding, laneTenant, first.Agent, first.Version)
		}
		return laneTenant, overwritten, nil
	}

	// Shared lane (pooled). In strict-lane mode the shared lane is refused for
	// agent-published planes — the residual forgery surface (WIRE-001) is the
	// shared lane, so closing it means requiring the namespaced lane.
	if strict {
		return "", false, ErrSharedLaneForbidden
	}
	// Non-strict: the claimed pair must exist in the registry (reduces but does
	// not eliminate the forgery surface — a known-registered pair can still be
	// forged by a credential holder; that residual is documented above).
	if binding != nil {
		if err := binding.Verify(ctx, first.Tenant, first.Agent); err != nil {
			return "", false, err
		}
		recordVersion(ctx, binding, first.Tenant, first.Agent, first.Version)
	}
	return first.Tenant, false, nil
}
