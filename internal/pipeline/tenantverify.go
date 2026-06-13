// SPDX-License-Identifier: LicenseRef-probectl-TBD

package pipeline

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/imfeelingtheagi/probectl/internal/store"
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
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

// Verify implements TenantBinding.
func (b *RegistryBinding) Verify(ctx context.Context, tenantID, agentID string) error {
	if tenantID == "" {
		return ErrNoTenant
	}
	if agentID == "" {
		return ErrTenantNotBound // an unattributable record is never authoritative
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
			return nil
		})
	if err != nil {
		// Lookup failure ≠ "not bound", but both REJECT: fail closed.
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
type Identity struct{ Tenant, Agent string }

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
	}
	return first.Tenant, false, nil
}
