// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License. See ee/LICENSE.
// Production use requires a valid commercial agreement. Resale additionally
// requires an MSP entitlement and reseller agreement.

package remediation

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/entity"
	rem "github.com/ctlplne/probectl/internal/remediation"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestRoutingTransferReviewBindsTheExactBlastLimitAndTenant(t *testing.T) {
	service := &Service{maxBlastRadius: 64}
	preview := rem.RoutingTransferDryRun{ExactPrefix: "203.0.113.0/26", MovedPeakBPS: "3/2"}
	for _, tc := range []struct {
		name, limit string
		want        int
		err         error
	}{
		{name: "within_exact_limit", limit: "3/2", want: 64},
		{name: "over_exact_limit", limit: "149/100", err: rem.ErrBlastRadiusExceeded},
		{name: "unknown_limit", limit: "", err: rem.Error{Code: "validation", Message: "set the exact peak traffic limit for moving this prefix"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := service.routingTransferApprovalBound(preview, tc.limit)
			if got != tc.want || !errors.Is(err, tc.err) {
				t.Errorf("bound %q: got %d, %v", tc.limit, got, err)
			}
		})
	}
	const tenant = "11111111-1111-4111-8111-111111111111"
	preview.ContextID = "22222222-2222-4222-8222-222222222222"
	preview.RouterID = "33333333-3333-4333-8333-333333333333"
	preview.ArchiveAgentID, preview.ArchiveSourceRef = "archive-agent", "192.0.2.1"
	preview.CandidatePeer = "192.0.2.2"
	preview.CurrentInboundPolicy, preview.ProposedInboundPolicy = "CURRENT", "PROPOSED"
	preview.Withdraw = []string{"restore CURRENT"}
	if !hasRoutingTransferRollback(tenant, preview) {
		t.Fatal("complete owned rollback was refused")
	}
	stored := storedRoutingTransferReview{Version: 1, Selection: json.RawMessage(`{"z":1,"a":2}`), Scope: "owned",
		Review: rem.RoutingTransferReview{Preview: preview, MaxMovedBPS: "3/2", BlastRadius: 64, ExpiresAt: time.Unix(1_800_000_000, 0).UTC()}}
	fingerprint, err := routingTransferReviewFingerprint(tenant, stored)
	if err != nil {
		t.Fatal(err)
	}
	stored.Review.Fingerprint = fingerprint
	stored.Selection = json.RawMessage(`{"a":2,"z":1}`)
	raw, err := json.Marshal(stored)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeStoredRoutingTransferReview(tenant, raw); err != nil {
		t.Fatalf("JSON representation changed an otherwise exact review: %v", err)
	}
	if _, err := decodeStoredRoutingTransferReview("22222222-2222-4222-8222-222222222222", raw); err == nil {
		t.Fatal("a review fingerprint crossed the tenant boundary")
	}
	t.Run("rollback_requires_the_recorded_approval_and_current_grant", func(t *testing.T) {
		assertStoredRoutingTransferRollback(t, tenant, raw, stored.Review)
	})
	stored.Review.Preview.ArchiveSourceRef = "192.0.2.99"
	altered, err := json.Marshal(stored)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeStoredRoutingTransferReview(tenant, altered); err == nil {
		t.Fatal("a different archive source retained the original rollback fingerprint")
	}
	t.Run("exclusive_deadline", func(t *testing.T) {
		end := stored.Review.ExpiresAt
		rollback := rem.RoutingTransferRollback{ApprovalExpiresAt: end}
		if got := rollback.StateAt(end.Add(-time.Nanosecond)); got != rem.RoutingTransferApprovalActive {
			t.Fatalf("before approval deadline, got %q", got)
		}
		if got := rollback.StateAt(end); got != rem.RoutingTransferApprovalExpired {
			t.Fatalf("at approval deadline, got %q", got)
		}
		rollback.WithdrawRequested = &end
		if got := rollback.StateAt(end.Add(time.Hour)); got != rem.RoutingTransferWithdrawalRequested {
			t.Fatalf("after recorded withdrawal, got %q", got)
		}
	})
}

func assertStoredRoutingTransferRollback(t *testing.T, tenant string, review []byte, expected rem.RoutingTransferReview) {
	t.Helper()
	preview := expected.Preview
	approvedAt := expected.ExpiresAt.Add(-time.Minute)
	older := approvedAt.Add(-time.Nanosecond)
	later := expected.ExpiresAt.Add(time.Minute)
	validApproval := map[string]any{
		"version": 1, "review_fingerprint": expected.Fingerprint, "approved_by_user_id": "reviewer-id",
		"approved_at": approvedAt, "expires_at": later,
	}
	payload, err := json.Marshal(validApproval)
	if err != nil {
		t.Fatal(err)
	}
	loaded := loadedRoutingTransferReview{review: review, approval: payload,
		proposal: rem.Proposal{State: rem.StateApproved, Target: preview.ExactPrefix,
			ProposedUserID: "proposer-id", DecidedBy: "user:reviewer", DecidedAt: &approvedAt}}
	scope := tenancy.Scope{Tenant: tenancy.ID(tenant)}
	refusal := errors.New("source grant refused")
	authorize := func(_ context.Context, sc tenancy.Scope, contextID, routerID string, source entity.SourceKey) error {
		if sc.Tenant.String() != tenant || contextID != preview.ContextID || routerID != preview.RouterID ||
			source != (entity.SourceKey{AgentID: preview.ArchiveAgentID, Kind: entity.DeviceTarget, SourceRef: preview.ArchiveSourceRef}) {
			t.Fatalf("the rollback read checked the wrong source or tenant: %+v", source)
		}
		return nil
	}
	got, err := storedRoutingTransferRollback(t.Context(), scope, loaded, authorize)
	if err != nil || !got.ApprovalExpiresAt.Equal(expected.ExpiresAt) || !slices.Equal(got.Withdraw, preview.Withdraw) {
		t.Fatalf("owned rollback lost the original commands or deadline: %+v, %v", got, err)
	}
	denied, err := storedRoutingTransferRollback(t.Context(), scope, loaded,
		func(context.Context, tenancy.Scope, string, string, entity.SourceKey) error { return refusal })
	if !errors.Is(err, refusal) || len(denied.Withdraw) != 0 {
		t.Fatalf("a removed source grant exposed rollback: %+v, %v", denied, err)
	}
	for _, tc := range []struct {
		name  string
		scope tenancy.Scope
		edit  func(*loadedRoutingTransferReview)
	}{
		{"sibling tenant", tenancy.Scope{Tenant: "22222222-2222-4222-8222-222222222222"}, func(*loadedRoutingTransferReview) {}},
		{"missing approval", scope, func(r *loadedRoutingTransferReview) { r.approval = nil }},
		{"unapproved proposal", scope, func(r *loadedRoutingTransferReview) { r.proposal.State = rem.StateProposed }},
		{"wrong target", scope, func(r *loadedRoutingTransferReview) { r.proposal.Target = "203.0.113.64/26" }},
		{"self approval", scope, func(r *loadedRoutingTransferReview) { r.proposal.ProposedUserID = "reviewer-id" }},
		{"withdrawal preceding approval", scope, func(r *loadedRoutingTransferReview) { r.withdrawn = &older }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			candidate := loaded
			tc.edit(&candidate)
			rejected, err := storedRoutingTransferRollback(t.Context(), tc.scope, candidate,
				func(context.Context, tenancy.Scope, string, string, entity.SourceKey) error {
					t.Fatal("an invalid stored approval reached authorization")
					return nil
				})
			if err == nil || len(rejected.Withdraw) != 0 {
				t.Fatalf("invalid stored approval exposed commands: %+v, %v", rejected, err)
			}
		})
	}
}
