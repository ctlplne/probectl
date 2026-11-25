// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License. See ee/LICENSE.
// Production use requires a valid commercial agreement. Resale additionally
// requires an MSP entitlement and reseller agreement.

//go:build integration

package remediation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/entity"
	rem "github.com/ctlplne/probectl/internal/remediation"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestRoutingTransferReviewStoresDistinctOwnedApprovals(t *testing.T) {
	pool := itPool(t)
	t.Cleanup(pool.Close)
	store := NewPGStore(pool)
	service := New(store, &fakeEstimator{}, NewTenantAudit(pool), Config{ApprovalsEnabled: true, MaxBlastRadius: 128})
	run, err := crypto.UUIDv4()
	if err != nil {
		t.Fatal(err)
	}
	type lane struct {
		tenant, id, fingerprint string
		proposer, reviewer      context.Context
		prepare                 rem.RoutingTransferReviewPrepare
		expires                 time.Time
	}
	var lanes [2]lane
	fingerprints := [2]string{strings.Repeat("a", 64), strings.Repeat("b", 64)}
	for i := range lanes {
		l := &lanes[i]
		l.tenant = itTenant(t, pool, fmt.Sprintf("it-transfer-%s-%d", run[:8], i))
		l.proposer = itActor(t, pool, l.tenant, "transfer-proposer@example.test")
		l.reviewer = itActor(t, pool, l.tenant, "transfer-reviewer@example.test")
		fingerprint := fingerprints[i]
		l.prepare = routingTransferReviewTestEvidence(l.tenant, fingerprint, fmt.Sprintf("%d", 120+i), time.Now().Add(4*time.Minute))
		proposal, err := service.ProposeRoutingTransfer(l.proposer, l.tenant, "user:proposer", json.RawMessage(`{"archive_id":"route-archive"}`), fingerprint, "180", l.prepare)
		if err != nil || proposal.State != rem.StateProposed || proposal.DryRun.BlastRadius != 64 {
			t.Fatalf("propose lane %d: %+v, %v", i, proposal, err)
		}
		l.id = proposal.ID
		preview, err := service.GetRoutingTransfer(l.reviewer, l.tenant, l.id, l.prepare)
		if err != nil || preview.Preview.PreviewFingerprint != fingerprint ||
			preview.ValidUntil.IsZero() || !preview.ValidUntil.Equal(preview.ExpiresAt) {
			t.Fatalf("review lane %d: %+v, %v", i, preview, err)
		}
		l.fingerprint = preview.Fingerprint
		l.expires = preview.ExpiresAt
	}
	shorter := lanes[0].expires.Add(-time.Minute).Truncate(time.Microsecond)
	shortenedEvidence := func(ctx context.Context, selection json.RawMessage) (rem.RoutingTransferDryRun, rem.RTBHImpactPublication, error) {
		preview, publication, err := lanes[0].prepare(ctx, selection)
		preview.SourceValidUntil = shorter
		return preview, publication, err
	}
	for i, l := range lanes {
		prepare, expected := l.prepare, l.expires
		if i == 0 {
			prepare, expected = shortenedEvidence, shorter
		}
		review, err := service.GetRoutingTransfer(l.reviewer, l.tenant, l.id, prepare)
		if err != nil || !review.ValidUntil.Equal(expected) || !review.ExpiresAt.Equal(l.expires) || review.Fingerprint != l.fingerprint {
			t.Fatalf("lane %d did not return its current deadline alongside the stored review: %+v, %v", i, review, err)
		}
	}
	for i, l := range lanes {
		other := lanes[1-i]
		if _, err := service.GetRoutingTransfer(l.reviewer, l.tenant, other.id, l.prepare); err == nil {
			t.Fatalf("lane %d read a sibling proposal", i)
		}
		if _, err := service.ApproveRoutingTransfer(l.reviewer, l.tenant, "user:reviewer", other.id, other.fingerprint, "", l.prepare); err == nil {
			t.Fatalf("lane %d approved a sibling proposal", i)
		}
		if _, err := service.ApproveRoutingTransfer(l.proposer, l.tenant, "user:proposer", l.id, l.fingerprint, "", l.prepare); !errors.Is(err, rem.ErrSelfApproval) {
			t.Fatalf("lane %d self approval: %v", i, err)
		}
		if _, err := service.ApproveRoutingTransfer(l.reviewer, l.tenant, "user:reviewer", l.id, other.fingerprint, "", l.prepare); err == nil {
			t.Fatalf("lane %d accepted a sibling fingerprint", i)
		}
		assertRoutingTransferDecisionRequiresPayload(t, store, l.reviewer, l.tenant, l.id)
		assertRoutingTransferReviewRefusesAConcurrentDecision(t, service, store, l.reviewer, l.tenant, l.id, l.fingerprint, l.prepare)
		result, err := service.ApproveRoutingTransfer(l.reviewer, l.tenant, "user:reviewer", l.id, l.fingerprint, "reviewed exact prefix", l.prepare)
		if err != nil || result.State != rem.StateApproved || result.DecidedAt == nil {
			t.Fatalf("approve lane %d: %+v, %v", i, result, err)
		}

		handedOff, err := service.GetRoutingTransfer(l.reviewer, l.tenant, l.id, l.prepare)
		if err != nil || handedOff.Decision == nil || handedOff.Fingerprint != l.fingerprint ||
			handedOff.Decision.ApprovedBy != "user:reviewer" || !handedOff.Decision.ApprovedAt.Equal(*result.DecidedAt) ||
			!handedOff.Decision.ValidUntil.After(handedOff.Decision.ApprovedAt) || !handedOff.ValidUntil.Equal(handedOff.Decision.ValidUntil) {
			t.Fatalf("approved review reload lane %d: %+v, %v", i, handedOff, err)
		}
		if i == 0 {
			review, err := service.GetRoutingTransfer(l.reviewer, l.tenant, l.id, shortenedEvidence)
			if err != nil || review.Decision == nil || !review.ValidUntil.Equal(shorter) || !review.Decision.ValidUntil.Equal(shorter) {
				t.Fatalf("approved review outlived the current source lease: %+v, %v", review, err)
			}
		}
		if _, err := service.GetRoutingTransfer(other.reviewer, other.tenant, l.id, other.prepare); err == nil {
			t.Fatalf("lane %d exposed an approved review to its sibling", i)
		}
	}
	service.withNow(func() time.Time { return lanes[0].expires.Add(time.Hour) })
	for i, l := range lanes {
		other := lanes[1-i]
		authorize := func(_ context.Context, sc tenancy.Scope, contextID, routerID string, source entity.SourceKey) error {
			if sc.Tenant.String() != l.tenant || contextID != rollbackTestContext || routerID != rollbackTestRouter ||
				source != (entity.SourceKey{AgentID: "archive-" + fingerprints[i][:1], Kind: entity.DeviceTarget, SourceRef: "192.0.2.1"}) {
				return tenancy.ErrNoTenant
			}
			return nil
		}
		expired, err := service.GetRoutingTransferRollback(l.reviewer, l.tenant, l.id, authorize)
		if err != nil || expired.State != rem.RoutingTransferApprovalExpired || expired.Fingerprint != l.fingerprint ||
			expired.ContextID != rollbackTestContext || expired.RouterID != rollbackTestRouter ||
			!slices.Equal(expired.Withdraw, []string{"restore exact policy " + fingerprints[i][:1]}) {
			t.Fatalf("lane %d lost its exact rollback after expiry: %+v %v", i, expired, err)
		}
		if _, err := service.GetRoutingTransferRollback(l.reviewer, l.tenant, other.id, authorize); err == nil {
			t.Fatalf("lane %d read the sibling rollback", i)
		}
		if _, err := service.RequestRoutingTransferWithdrawal(l.reviewer, l.tenant, "user:reviewer", other.id, other.fingerprint, authorize); err == nil {
			t.Fatalf("lane %d requested withdrawal of the sibling's approval", i)
		}
		if _, err := service.RequestRoutingTransferWithdrawal(l.reviewer, l.tenant, "user:reviewer", l.id, other.fingerprint, authorize); err == nil {
			t.Fatalf("lane %d accepted a sibling withdrawal fingerprint", i)
		}
		denied := errors.New("archive source grant revoked")
		denySource := func(ctx context.Context, sc tenancy.Scope, contextID, routerID string, source entity.SourceKey) error {
			if err := authorize(ctx, sc, contextID, routerID, source); err != nil {
				return err
			}
			return denied
		}
		if refused, err := service.GetRoutingTransferRollback(l.reviewer, l.tenant, l.id, denySource); !errors.Is(err, denied) || len(refused.Withdraw) != 0 {
			t.Fatalf("lane %d returned rollback after removal of source authority: %+v %v", i, refused, err)
		}
		if refused, err := service.RequestRoutingTransferWithdrawal(l.reviewer, l.tenant, "user:reviewer", l.id, l.fingerprint, denySource); !errors.Is(err, denied) || refused.WithdrawRequested != nil {
			t.Fatalf("lane %d allowed withdrawal after removal of source authority: %+v %v", i, refused, err)
		}
		withdrawn, err := service.RequestRoutingTransferWithdrawal(l.reviewer, l.tenant, "user:reviewer", l.id, l.fingerprint, authorize)
		if err != nil || withdrawn.State != rem.RoutingTransferWithdrawalRequested || withdrawn.WithdrawRequested == nil ||
			!slices.Equal(withdrawn.Withdraw, expired.Withdraw) || !withdrawn.ApprovalExpiresAt.Equal(expired.ApprovalExpiresAt) {
			t.Fatalf("lane %d lost its immutable commands during withdrawal: %+v %v", i, withdrawn, err)
		}
		retry, err := service.RequestRoutingTransferWithdrawal(l.reviewer, l.tenant, "user:reviewer", l.id, l.fingerprint, authorize)
		if err != nil || retry.WithdrawRequested == nil || !retry.WithdrawRequested.Equal(*withdrawn.WithdrawRequested) {
			t.Fatalf("lane %d repeated withdrawal changed the marker: %+v %v", i, retry, err)
		}
		if err := tenancy.InTenant(tenancy.WithTenant(t.Context(), tenancy.ID(l.tenant)), pool,
			func(ctx context.Context, sc tenancy.Scope) error {
				var writes int
				if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE tenant_id=$1
					AND target=$2 AND action='remediation.routing_transfer_withdraw'`, l.tenant, l.id).Scan(&writes); err != nil {
					return err
				}
				if writes != 1 {
					return fmt.Errorf("expected one withdrawal audit event, got %d", writes)
				}
				return audit.TenantVerify(ctx, sc)
			}); err != nil {
			t.Fatalf("verify lane %d audit: %v", i, err)
		}
	}
}

const rollbackTestContext = "44444444-4444-4444-8444-444444444444"
const rollbackTestRouter = "55555555-5555-4555-8555-555555555555"

// The test supplies fixed, owned source evidence. It uses the production store,
// RLS, database transition and audit paths.
func routingTransferReviewTestEvidence(tenant, fingerprint, moved string, expires time.Time) rem.RoutingTransferReviewPrepare {
	return func(_ context.Context, _ json.RawMessage) (rem.RoutingTransferDryRun, rem.RTBHImpactPublication, error) {
		preview := rem.RoutingTransferDryRun{ExactPrefix: "203.0.113.0/26", PreviewFingerprint: fingerprint,
			MovedPeakBPS: moved, SourceValidUntil: expires, ContextID: rollbackTestContext, RouterID: rollbackTestRouter,
			ArchiveAgentID: "archive-" + fingerprint[:1], ArchiveSourceRef: "192.0.2.1",
			CandidatePeer: "192.0.2.2", CurrentInboundPolicy: "OLD", ProposedInboundPolicy: "REVIEWED",
			Withdraw: []string{"restore exact policy " + fingerprint[:1]}}
		publication := rem.RTBHImpactPublication{Scope: fingerprint, Publish: func(ctx context.Context, sc tenancy.Scope, _ string, mutate func(context.Context, tenancy.Scope) error) error {
			if sc.Tenant.String() != tenant {
				return tenancy.ErrNoTenant
			}
			if err := tenancy.LockTenantAuditStream(ctx, sc.Q, tenant); err != nil {
				return err
			}
			return mutate(ctx, sc)
		}}
		return preview, publication, nil
	}
}

func assertRoutingTransferDecisionRequiresPayload(t *testing.T, store *PGStore, reviewer context.Context, tenant, proposal string) {
	t.Helper()
	scoped, err := remediationTenantContext(reviewer, tenant)
	if err != nil {
		t.Fatal(err)
	}
	err = tenancy.InTenant(scoped, store.pool, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `UPDATE remediation_proposals SET state='approved' WHERE tenant_id=$1 AND id=$2`, tenant, proposal)
		return err
	})
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "23514" || pgErr.ConstraintName != "remediation_proposals_routing_transfer_approval_v1" {
		t.Fatalf("old decision statement bypassed the approval payload constraint: %v", err)
	}
}

// A generic rejection holds the proposal row first, then takes the audit
// lock. Approval holds the audit lock after its contract check. A conflict
// must return for a fresh review without waiting for the held row.
func assertRoutingTransferReviewRefusesAConcurrentDecision(t *testing.T, service *Service, store *PGStore,
	reviewer context.Context, tenant, id, fingerprint string, prepare rem.RoutingTransferReviewPrepare) {
	t.Helper()
	scoped, err := remediationTenantContext(reviewer, tenant)
	if err != nil {
		t.Fatal(err)
	}
	err = tenancy.InTenant(scoped, store.pool, func(ctx context.Context, sc tenancy.Scope) error {
		var locked string
		if err := sc.Q.QueryRow(ctx, `SELECT id::text FROM remediation_proposals WHERE tenant_id=$1 AND id=$2 FOR UPDATE`, tenant, id).Scan(&locked); err != nil {
			return err
		}
		deadline, cancel := context.WithTimeout(reviewer, 3*time.Second)
		defer cancel()
		_, err := service.ApproveRoutingTransfer(deadline, tenant, "user:reviewer", locked, fingerprint, "", prepare)
		if !errors.Is(err, changedRTBHReview()) {
			return fmt.Errorf("approval against a held proposal: got %v, expected review conflict", err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
