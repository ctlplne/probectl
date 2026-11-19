// SPDX-License-Identifier: BUSL-1.1
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package tenantlife

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type prospectErasure struct {
	engagement      store.ProspectEngagement
	evidence        store.ProspectErasureEvidence
	deliveryActor   string
	revalidate      func(context.Context, tenancy.Scope) error
	resumeFenceHash string
}

// EraseProspect reuses the tenant erasure engine. The first irreversible
// transition requires the exact consent and delivery in the app-role scope
// and a current authority and report-source check under the writer lease.
func (e *Engine) EraseProspect(ctx context.Context, tenant string, engagement store.ProspectEngagement,
	evidence store.ProspectErasureEvidence, deliveryActor string, revalidate func(context.Context, tenancy.Scope) error) (Attestation, error) {
	bound, ok := tenancy.FromContext(ctx)
	if e.pool == nil || !ok || tenant != bound.String() || !engagement.HasCurrentDeliveryConsent() ||
		engagement.OwnerID == "" || engagement.TenantSlug == "" || revalidate == nil || deliveryActor == "" ||
		evidence.ArtifactID == "" || evidence.ArtifactID != engagement.AssessmentArtifactID || evidence.DestinationID != engagement.DestinationID {
		return Attestation{}, errors.New("current scoped prospect erasure evidence is required")
	}
	request := &prospectErasure{engagement: engagement, evidence: evidence, deliveryActor: deliveryActor, revalidate: revalidate}
	return e.erase(ctx, tenant, engagement.TenantSlug, engagement.OwnerID, request)
}

// ResumeProspectErasure can finish a tenant whose authorized scheduled fence
// has already committed. A manual or uncommitted fence returns attempted=false.
func (e *Engine) ResumeProspectErasure(ctx context.Context, tenant string) (Attestation, bool, error) {
	bound, ok := tenancy.FromContext(ctx)
	if e.pool == nil || !ok || tenant != bound.String() {
		return Attestation{}, false, tenancy.ErrNoTenant
	}
	var request prospectErasure
	err := tenancy.InProvider(ctx, e.pool, func(ctx context.Context, q tenancy.Querier) error {
		return q.QueryRow(ctx, `SELECT t.slug,e.actor,e.hash FROM public.tenants t
		 JOIN public.provider_audit_events e ON e.target=t.id::text
		 WHERE t.id=$1 AND t.status='offboarding' AND t.audit_write_fenced_at IS NOT NULL
		 AND e.action='lifecycle.erase_fence' AND e.data ? 'scheduled_prospect' AND e.data_canonical IS NOT NULL
		 AND e.data->'scheduled_prospect'->>'tenant_slug'=t.slug
		 ORDER BY e.seq DESC LIMIT 1`, tenant).
			Scan(&request.engagement.TenantSlug, &request.engagement.OwnerID, &request.resumeFenceHash)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return Attestation{}, false, nil
	}
	if err != nil {
		return Attestation{}, false, err
	}
	if request.engagement.OwnerID == "" || request.engagement.TenantSlug == "" || len(request.resumeFenceHash) != 64 {
		return Attestation{}, false, errors.New("scheduled prospect fence receipt is incomplete")
	}
	attestation, err := e.erase(ctx, tenant, request.engagement.TenantSlug, request.engagement.OwnerID, &request)
	return attestation, true, err
}

func (e *Engine) fenceProspectErasure(ctx context.Context, tenant string, request *prospectErasure) error {
	if request.resumeFenceHash != "" {
		return tenancy.InProvider(ctx, e.pool, func(ctx context.Context, q tenancy.Querier) error {
			if err := lockErasureFence(ctx, q, tenant); err != nil {
				return err
			}
			return e.markErasureFenced(ctx, q, tenant, request.engagement.OwnerID, request)
		})
	}
	return tenancy.InTenant(ctx, e.pool, func(ctx context.Context, sc tenancy.Scope) error {
		if sc.Tenant.String() != tenant {
			return tenancy.ErrNoTenant
		}
		if err := lockErasureFence(ctx, sc.Q, tenant); err != nil {
			return err
		}
		witness, err := (store.ProspectEngagements{}).ErasureEvidence(ctx, sc, request.engagement, request.deliveryActor)
		if err != nil {
			return err
		}
		if witness == nil || !witness.DeliveredAt.Equal(request.evidence.DeliveredAt) {
			return errors.New("prospect consent or durable delivery changed before the erasure fence")
		}
		witness.DeliveredAt = request.evidence.DeliveredAt
		if *witness != request.evidence {
			return errors.New("prospect consent or durable delivery changed before the erasure fence")
		}
		if err := request.revalidate(ctx, sc); err != nil {
			return err
		}
		// All tenant data reads used the app role. The registry transition and
		// provider audit for this one tenant share the same transaction.
		if _, err := sc.Q.Exec(ctx, "SET LOCAL ROLE "+pgx.Identifier{tenancy.ProviderRole}.Sanitize()); err != nil {
			return fmt.Errorf("assume provider role for the tenant erasure fence: %w", err)
		}
		return e.markErasureFenced(ctx, sc.Q, tenant, request.engagement.OwnerID, request)
	})
}

func (p *prospectErasure) fenceAudit(ctx context.Context, q tenancy.Querier, tenant, slug, status string, fenced bool, data map[string]any) error {
	if err := tenancy.CheckQuarantine(tenant); err != nil {
		return err
	}
	if slug != p.engagement.TenantSlug {
		return errors.New("the confirmed prospect tenant slug changed")
	}
	if p.resumeFenceHash == "" {
		if fenced || status != "active" {
			return errors.New("the prospect is not active for scheduled erasure")
		}
		data["scheduled_prospect"] = map[string]any{
			"tenant_slug": slug, "revision": p.engagement.Revision, "consent_seq": p.evidence.ConsentAuditSequence, "consent_hash": p.evidence.ConsentAuditHash,
			"delivery_seq": p.evidence.DeliveryAuditSequence, "delivery_hash": p.evidence.DeliveryAuditHash,
			"assessment_sha256": p.evidence.BodySHA256, "assessment_bytes": p.evidence.BodyBytes,
		}
		return nil
	}
	var resume bool
	if err := q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM public.provider_audit_events
		 WHERE target=$1 AND actor=$2 AND hash=$3 AND action='lifecycle.erase_fence'
		 AND data->'scheduled_prospect'->>'tenant_slug'=$4 AND data_canonical IS NOT NULL)`, tenant, p.engagement.OwnerID, p.resumeFenceHash, slug).
		Scan(&resume); err != nil {
		return err
	}
	if !resume || !fenced || status != "offboarding" {
		return errors.New("the authorized scheduled prospect erasure fence is unavailable")
	}
	data["prospect_resume_fence_hash"] = p.resumeFenceHash
	return nil
}

func lockErasureFence(ctx context.Context, q tenancy.Querier, tenant string) error {
	if err := tenancy.LockTenantWrites(ctx, q, tenant); err != nil {
		return err
	}
	if err := audit.LockTenantStream(ctx, q, tenant); err != nil {
		return fmt.Errorf("lock tenant audit stream: %w", err)
	}
	return nil
}
