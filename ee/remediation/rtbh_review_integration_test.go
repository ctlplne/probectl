// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
// Licensed under the probectl Commercial Source License. See ee/LICENSE.
// Production use requires a valid commercial agreement. Resale additionally
// requires an MSP entitlement and reseller agreement.

//go:build integration

package remediation

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/auth"
	rem "github.com/ctlplne/probectl/internal/remediation"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type rtbhReviewFixtureSource struct {
	owner, scope string
	impact       rem.PrefixImpact
	refuse       bool
}

func (f *rtbhReviewFixtureSource) ObservePrefixImpact(ctx context.Context, tenant string, input rem.PrefixImpactInput, check func(context.Context) error) (rem.PrefixImpact, error) {
	prepared, err := f.PreparePrefixImpact(ctx, tenant, input, time.Time{}, check)
	return prepared.Impact, err
}

func (f *rtbhReviewFixtureSource) PreparePrefixImpact(ctx context.Context, tenant string, _ rem.PrefixImpactInput, end time.Time, check func(context.Context) error) (rem.RTBHImpactPublication, error) {
	if tenant != f.owner || (!end.IsZero() && !f.impact.To.Equal(end)) {
		return rem.RTBHImpactPublication{}, unavailableRTBHReview()
	}
	if err := check(ctx); err != nil {
		return rem.RTBHImpactPublication{}, err
	}
	return rem.RTBHImpactPublication{Impact: f.impact, Scope: f.scope,
		Publish: func(ctx context.Context, sc tenancy.Scope, _ string, mutation func(context.Context, tenancy.Scope) error) error {
			if f.refuse || sc.Tenant.String() != f.owner {
				return changedRTBHReview()
			}
			if err := audit.LockTenantStream(ctx, sc.Q, sc.Tenant.String()); err != nil {
				return err
			}
			return mutation(ctx, sc)
		}}, nil
}

func TestRTBHReviewPostgresKeepsExactEvidenceAndIndependentApproval(t *testing.T) {
	pool := itPool(t)
	t.Cleanup(pool.Close)
	suffix := time.Now().Format("150405.000000000")
	owner, sibling := itTenant(t, pool, "rtbh-pair-a-"+suffix), itTenant(t, pool, "rtbh-pair-b-"+suffix)
	proposer := itActor(t, pool, owner, "proposer@routing.invalid")
	reviewer := itActor(t, pool, owner, "reviewer@routing.invalid")
	foreign := itActor(t, pool, sibling, "reviewer@routing.invalid")
	rows := NewPGStore(pool)
	clock := time.Now().UTC().Truncate(time.Minute)
	end := clock.Add(-time.Minute)
	source := &rtbhReviewFixtureSource{owner: owner, scope: strings.Repeat("a", 64), impact: rem.PrefixImpact{
		Prefix: "192.0.2.0/26", From: end.Add(-time.Minute), To: end, Sampled: true, ObservedRecords: 8, ObservedAddresses: 3,
		Matched: rem.PrefixTraffic{Bytes: "9007199254740993", Packets: "101"}, KnownBenign: rem.PrefixTraffic{Bytes: "23", Packets: "3"},
		Unclassified: rem.PrefixTraffic{Bytes: "9007199254740970", Packets: "98"},
	}}
	service := New(rows, nil, NewTenantAudit(pool), Config{ApprovalsEnabled: true, MaxBlastRadius: 64, PrefixImpact: source}).
		withNow(func() time.Time { return clock })
	credential := func(context.Context) error { return nil }
	selection := rem.RTBHPreviewInput{Community: "64512:100", RoutingPolicyAgreed: true}
	preview, err := service.PreviewRTBH(proposer, owner, selection, credential)
	if err != nil || !validRTBHDigest(preview.Fingerprint) || preview.Impact != source.impact {
		t.Fatal("preview lost the exact modeled original population", err)
	}
	input := rem.RTBHProposalInput{Preview: selection, ObservedTo: end, PreviewFingerprint: preview.Fingerprint, MaxKnownBenignPackets: "2"}
	if _, err := service.ProposeRTBH(proposer, owner, "user:proposer", input, credential); !errors.Is(err, rem.ErrBlastRadiusExceeded) {
		t.Fatal("a proposal exceeded the declared benign collateral limit", err)
	}
	input.MaxKnownBenignPackets = "3"
	wrong := input
	wrong.PreviewFingerprint = strings.Repeat("b", 64)
	if _, err := service.ProposeRTBH(proposer, owner, "user:proposer", wrong, credential); err == nil {
		t.Fatal("a changed preview fingerprint produced a proposal")
	}
	proposal, err := service.ProposeRTBH(proposer, owner, "user:proposer", input, credential)
	if err != nil || proposal.State != rem.StateProposed || proposal.Kind != rem.KindRTBHReview || proposal.DryRun.BlastRadius != 64 ||
		proposal.Target != "" || proposal.DryRun.BlastRadius == source.impact.ObservedAddresses {
		t.Fatal("generic proposal output exposed private scope or used sampled destinations as the blast radius", err)
	}
	if _, err := service.GetRTBHReview(foreign, sibling, proposal.ID, credential); err == nil {
		t.Fatal("review crossed its PostgreSQL tenant boundary")
	}
	if _, err := rows.decide(reviewer, owner, proposal.ID, rem.StateApproved, "user:review", "plain", clock); !errors.Is(err, rem.ErrNotProposed) {
		t.Fatal("a direct ordinary transition bypassed the exact reviewed document", err)
	}
	review, err := service.GetRTBHReview(reviewer, owner, proposal.ID, credential)
	if err != nil || !validRTBHDigest(review.Fingerprint) || review.Fingerprint == preview.Fingerprint || review.MaxKnownBenignPackets != "3" ||
		review.Candidate.Impact.Matched.Bytes != "9007199254740993" || !review.ExpiresAt.Equal(end.Add(rtbhReviewLifetime)) {
		t.Fatal("review lost the approved limit, clock, exact amount or immutable comparison handle", err)
	}
	if _, err := service.ApproveRTBH(proposer, owner, "user:renamed-proposer", proposal.ID, review.Fingerprint, "", credential); !errors.Is(err, rem.ErrSelfApproval) {
		t.Fatal("the stable initiating account could review its own proposal", err)
	}
	token := auth.ClonePrincipal(auth.PrincipalFrom(reviewer))
	token.ViaBearerToken = true
	if _, err := service.ApproveRTBH(auth.WithPrincipal(reviewer, token), owner, "user:reviewer", proposal.ID, review.Fingerprint, "", credential); !errors.Is(err, rem.ErrApprovalActorUnavailable) {
		t.Fatal("an API credential approved a human-gated routing review", err)
	}
	if _, err := service.ApproveRTBH(reviewer, owner, "user:reviewer", proposal.ID, preview.Fingerprint, "", credential); err == nil {
		t.Fatal("approval accepted a preview handle that omitted the final collateral policy")
	}
	source.scope = strings.Repeat("c", 64)
	if _, err := service.ApproveRTBH(reviewer, owner, "user:reviewer", proposal.ID, review.Fingerprint, "", credential); err == nil {
		t.Fatal("a source change approved old collateral")
	}
	source.scope = strings.Repeat("a", 64)
	source.refuse = true
	if _, err := service.ApproveRTBH(reviewer, owner, "user:reviewer", proposal.ID, review.Fingerprint, "", credential); err == nil {
		t.Fatal("a publication-scope refusal committed its decision")
	}
	source.refuse = false
	saved, err := service.ApproveRTBH(reviewer, owner, "user:reviewer", proposal.ID, review.Fingerprint, "checked own evidence", credential)
	if err != nil || saved.State != rem.StateApproved || saved.DecidedBy != "user:reviewer" {
		t.Fatal("the distinct current reviewer could not commit one scoped approval", err)
	}
	for _, tenant := range []string{owner, sibling} {
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
		if err := tenancy.InTenant(ctx, pool, func(ctx context.Context, sc tenancy.Scope) error {
			var count int
			if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE tenant_id=$1 AND target=$2 AND action='remediation.approve'`, tenant, proposal.ID).Scan(&count); err != nil {
				return err
			}
			want := 0
			if tenant == owner {
				want = 1
			}
			if count != want {
				t.Fatalf("tenant approval audit count = %d, want %d", count, want)
			}
			return audit.TenantVerify(ctx, sc)
		}); err != nil {
			t.Fatal(err)
		}
	}
}
