// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License. See ee/LICENSE.
// Production use requires a valid commercial agreement. Resale additionally
// requires an MSP entitlement and reseller agreement.

package remediation

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	rem "github.com/ctlplne/probectl/internal/remediation"
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
