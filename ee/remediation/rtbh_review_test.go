// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
// Licensed under the probectl Commercial Source License. See ee/LICENSE.
// Production use requires a valid commercial agreement. Resale additionally
// requires an MSP entitlement and reseller agreement.

package remediation

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/license"
	rem "github.com/ctlplne/probectl/internal/remediation"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type prefixImpactSourceFunc func(context.Context, string, rem.PrefixImpactInput, func(context.Context) error) (rem.PrefixImpact, error)

func (f prefixImpactSourceFunc) ObservePrefixImpact(ctx context.Context, tenant string, input rem.PrefixImpactInput,
	check func(context.Context) error) (rem.PrefixImpact, error) {
	return f(ctx, tenant, input, check)
}

func TestRTBHPreviewRequiresPolicyAndKeepsTheProposalLedgerReadOnly(t *testing.T) {
	ctx := remediationTestActor(t.Context(), testTenant, testProposerID)
	var reads int
	memory := NewMemStore()
	source := prefixImpactSourceFunc(func(ctx context.Context, tenant string, _ rem.PrefixImpactInput, check func(context.Context) error) (rem.PrefixImpact, error) {
		if tenant != testTenant {
			t.Fatal("the preview source received a different tenant", tenant)
		}
		if err := check(ctx); err != nil {
			return rem.PrefixImpact{}, err
		}
		reads++
		return rem.PrefixImpact{Prefix: "192.0.2.0/24", Matched: rem.PrefixTraffic{Bytes: "9007199254740993", Packets: "80"},
			KnownBenign: rem.PrefixTraffic{Bytes: "300", Packets: "3"}}, nil
	})
	svc := rem.GateServiceWrites(New(memory, nil, nil, Config{PrefixImpact: source}), license.WriteCapability(func() bool { return false }))
	previewer, ok := svc.(rem.RTBHPreviewer)
	if !ok {
		t.Fatal("the read-only license seam lost traffic preview")
	}
	verify := func(ctx context.Context) error { return ctx.Err() }
	for _, input := range []rem.RTBHPreviewInput{
		{Community: "64512:100"},
		{Community: "064512:100", RoutingPolicyAgreed: true},
		{Community: "64512:65536", RoutingPolicyAgreed: true},
	} {
		if _, err := previewer.PreviewRTBH(ctx, testTenant, input, verify); err == nil || reads != 0 {
			t.Fatal("an unconfirmed or invalid policy reached the source", err)
		}
	}
	input := rem.RTBHPreviewInput{Community: "64512:100", RoutingPolicyAgreed: true}
	if _, err := previewer.PreviewRTBH(ctx, testTenantB, input, verify); !errors.Is(err, rem.ErrApprovalActorUnavailable) || reads != 0 {
		t.Fatal("a foreign tenant selected the collateral source", err)
	}
	got, err := previewer.PreviewRTBH(ctx, testTenant, input, verify)
	if err != nil || got.Announcement != (rem.RTBHAnnouncement{Family: "ipv4", Prefix: "192.0.2.0/24", Community: "64512:100"}) ||
		got.Impact.Matched.Bytes != "9007199254740993" || got.Impact.KnownBenign.Bytes != "300" || reads != 1 {
		t.Fatal("the reviewed observation and route attributes did not stay together", got, err)
	}
	if proposals, err := memory.List(ctx, testTenant); err != nil || len(proposals) != 0 {
		t.Fatal("an evidence preview wrote a proposal", err)
	}
}

// Use the existing audit-aware in-memory ledger. The recording fixture keeps
// the exact evidence bytes beside each proposal and calls the publication
// fence before either mutation. The shipped integration test covers SQL.
type rtbhReviewFixtureStore struct {
	*MemStore
	evidence map[string][]byte
}

func (m *rtbhReviewFixtureStore) InsertRTBHAudited(ctx context.Context, tenant string, proposal rem.Proposal, raw []byte,
	current rem.RTBHImpactPublication, audit AuditSink, event AuditEvent) (rem.Proposal, error) {
	var saved rem.Proposal
	err := current.Publish(ctx, tenancy.Scope{Tenant: tenancy.ID(tenant)}, "remediation.propose", func(ctx context.Context, _ tenancy.Scope) error {
		var err error
		saved, err = m.InsertAudited(ctx, tenant, proposal, audit, event)
		if err == nil {
			m.evidence[saved.ID] = bytes.Clone(raw)
		}
		return err
	})
	return saved, err
}

func (m *rtbhReviewFixtureStore) LoadRTBHReview(ctx context.Context, tenant, id string) (rem.Proposal, []byte, error) {
	proposal, err := m.Get(ctx, tenant, id)
	if err != nil {
		return rem.Proposal{}, nil, err
	}
	return proposal, bytes.Clone(m.evidence[id]), nil
}

func (m *rtbhReviewFixtureStore) ApproveRTBHAudited(ctx context.Context, tenant, id, actor, note string, at time.Time,
	expected []byte, current rem.RTBHImpactPublication, audit AuditSink, event AuditEvent) (rem.Proposal, error) {
	var saved rem.Proposal
	err := current.Publish(ctx, tenancy.Scope{Tenant: tenancy.ID(tenant)}, "remediation.approve", func(ctx context.Context, _ tenancy.Scope) error {
		if !bytes.Equal(expected, m.evidence[id]) {
			return changedRTBHReview()
		}
		var err error
		saved, err = m.DecideAudited(ctx, tenant, id, rem.StateApproved, actor, note, at, audit, event)
		return err
	})
	return saved, err
}

type rtbhReviewFixtureSource struct {
	impact        rem.PrefixImpact
	scope         string
	beforePublish func()
	publications  []string
}

func (*rtbhReviewFixtureSource) ObservePrefixImpact(context.Context, string, rem.PrefixImpactInput, func(context.Context) error) (rem.PrefixImpact, error) {
	return rem.PrefixImpact{}, errors.New("the review must use the source's scoped publication")
}

func (s *rtbhReviewFixtureSource) PreparePrefixImpact(ctx context.Context, tenant string, input rem.PrefixImpactInput, observedTo time.Time,
	check func(context.Context) error) (rem.RTBHImpactPublication, error) {
	if tenant != testTenant || input.WholeViewID != "owned-view" || (!observedTo.IsZero() && !observedTo.Equal(s.impact.To)) {
		return rem.RTBHImpactPublication{}, changedRTBHReview()
	}
	if err := check(ctx); err != nil {
		return rem.RTBHImpactPublication{}, err
	}
	return rem.RTBHImpactPublication{Impact: s.impact, Scope: s.scope,
		Publish: func(ctx context.Context, sc tenancy.Scope, permission string, mutate func(context.Context, tenancy.Scope) error) error {
			if string(sc.Tenant) != tenant {
				return rem.ErrApprovalActorUnavailable
			}
			if err := check(ctx); err != nil {
				return err
			}
			if s.beforePublish != nil {
				s.beforePublish()
			}
			if err := mutate(ctx, sc); err != nil {
				return err
			}
			s.publications = append(s.publications, permission)
			return nil
		}}, nil
}

type rtbhReviewFixture struct {
	service  *Service
	store    *rtbhReviewFixtureStore
	source   *rtbhReviewFixtureSource
	audit    *recAudit
	now      time.Time
	proposer context.Context
	reviewer context.Context
}

func newRTBHReviewFixture(t *testing.T) *rtbhReviewFixture {
	t.Helper()
	f := &rtbhReviewFixture{
		store:    &rtbhReviewFixtureStore{MemStore: NewMemStore(), evidence: make(map[string][]byte)},
		audit:    &recAudit{},
		now:      fixedNow.Add(time.Minute),
		proposer: remediationTestActor(t.Context(), testTenant, testProposerID),
		reviewer: remediationTestActor(t.Context(), testTenant, testReviewerID),
		source: &rtbhReviewFixtureSource{scope: strings.Repeat("a", 64), impact: rem.PrefixImpact{
			Prefix: "192.0.2.0/28", From: fixedNow.Add(-time.Minute), To: fixedNow,
			Matched: rem.PrefixTraffic{Bytes: "9007199254740995", Packets: "100"}, KnownBenign: rem.PrefixTraffic{Bytes: "300", Packets: "3"},
		}},
	}
	f.service = New(f.store, nil, f.audit.fn(), Config{ApprovalsEnabled: true, MaxBlastRadius: 16, PrefixImpact: f.source}).
		withNow(func() time.Time { return f.now })
	return f
}

func (f *rtbhReviewFixture) displayed(t *testing.T) rem.RTBHProposalInput {
	t.Helper()
	input := rem.RTBHPreviewInput{PrefixImpactInput: rem.PrefixImpactInput{WholeViewID: "owned-view"}, Community: "64512:100", RoutingPolicyAgreed: true}
	preview, err := f.service.PreviewRTBH(f.proposer, testTenant, input, context.Context.Err)
	if err != nil {
		t.Fatal("preview current evidence", err)
	}
	return rem.RTBHProposalInput{Preview: input, ObservedTo: preview.Impact.To, PreviewFingerprint: preview.Fingerprint, MaxKnownBenignPackets: "3"}
}

func (f *rtbhReviewFixture) propose(t *testing.T, input rem.RTBHProposalInput) rem.Proposal {
	t.Helper()
	p, err := f.service.ProposeRTBH(f.proposer, testTenant, "proposer", input, context.Context.Err)
	if err != nil || p.TenantID != testTenant || p.ProposedUserID != testProposerID || p.State != rem.StateProposed || p.Kind != rem.KindRTBHReview {
		t.Fatal("expected an owned proposed review", p, err)
	}
	return p
}

func assertRTBHErrorCode(t *testing.T, err error, code string) {
	t.Helper()
	var domain rem.Error
	if !errors.As(err, &domain) || domain.Code != code {
		t.Fatalf("error = %v, want %s", err, code)
	}
}

func TestRTBHReviewBindsExactEvidenceAndIndependentApproval(t *testing.T) {
	f := newRTBHReviewFixture(t)
	input := f.displayed(t)
	p := f.propose(t, input)
	review, err := f.service.GetRTBHReview(f.reviewer, testTenant, p.ID, context.Context.Err)
	if err != nil || review.Fingerprint == "" || review.Fingerprint == input.PreviewFingerprint || review.Candidate.Fingerprint != input.PreviewFingerprint ||
		review.BlastRadius != 16 || review.MaxKnownBenignPackets != "3" || review.Candidate.Impact.Matched.Bytes != "9007199254740995" {
		t.Fatal("stored review lost exact observations or policy", review, err)
	}
	sibling := remediationTestActor(t.Context(), testTenantB, testReviewerID)
	_, err = f.service.GetRTBHReview(sibling, testTenantB, p.ID, context.Context.Err)
	assertRTBHErrorCode(t, err, "not_found")
	_, err = f.service.ApproveRTBH(sibling, testTenantB, "reviewer", p.ID, review.Fingerprint, "", context.Context.Err)
	assertRTBHErrorCode(t, err, "not_found")
	_, err = f.service.ApproveRTBH(f.proposer, testTenant, "same account with another label", p.ID, review.Fingerprint, "", context.Context.Err)
	if !errors.Is(err, rem.ErrSelfApproval) {
		t.Fatal("the initiating account approved its own proposal", err)
	}
	bearer := auth.WithPrincipal(t.Context(), &auth.Principal{TenantID: testTenant, UserID: testReviewerID, ViaBearerToken: true})
	_, err = f.service.ApproveRTBH(bearer, testTenant, "reviewer", p.ID, review.Fingerprint, "", context.Context.Err)
	if !errors.Is(err, rem.ErrApprovalActorUnavailable) {
		t.Fatal("a bearer credential acted as an interactive reviewer", err)
	}
	_, err = f.service.ApproveRTBH(f.reviewer, testTenant, "reviewer", p.ID, input.PreviewFingerprint, "", context.Context.Err)
	assertRTBHErrorCode(t, err, "review_changed")

	approved, err := f.service.ApproveRTBH(f.reviewer, testTenant, "reviewer", p.ID, review.Fingerprint, "verified exact evidence", context.Context.Err)
	if err != nil || approved.State != rem.StateApproved || approved.DecidedBy != "reviewer" || approved.Decision != "verified exact evidence" {
		t.Fatal("the independent decision was not saved", approved, err)
	}
	if _, err := f.service.ApproveRTBH(f.reviewer, testTenant, "reviewer", p.ID, review.Fingerprint, "duplicate", context.Context.Err); !errors.Is(err, rem.ErrNotProposed) {
		t.Fatal("a replay changed the decision", err)
	}
	if !slices.Equal(f.source.publications, []string{"remediation.propose", "remediation.approve"}) ||
		!slices.Equal(f.audit.actions(), []string{"remediation.propose", "remediation.approve_blocked", "remediation.approve"}) {
		t.Fatal("published mutations or decision audit differed", f.source.publications, f.audit.actions())
	}
}

func TestRTBHReviewRefusesChangedEvidenceAndExpiryAtPublication(t *testing.T) {
	f := newRTBHReviewFixture(t)
	input := f.displayed(t)
	tooLow := input
	tooLow.MaxKnownBenignPackets = "2"
	if _, err := f.service.ProposeRTBH(f.proposer, testTenant, "proposer", tooLow, context.Context.Err); !errors.Is(err, rem.ErrBlastRadiusExceeded) {
		t.Fatal("the collateral limit was not applied", err)
	}
	p := f.propose(t, input)
	review, err := f.service.GetRTBHReview(f.reviewer, testTenant, p.ID, context.Context.Err)
	if err != nil {
		t.Fatal("read current review", err)
	}
	approve := func(check func(context.Context) error) error {
		_, err := f.service.ApproveRTBH(f.reviewer, testTenant, "reviewer", p.ID, review.Fingerprint, "reviewed", check)
		return err
	}
	previousScope := f.source.scope
	f.source.scope = strings.Repeat("b", 64)
	_, err = f.service.GetRTBHReview(f.reviewer, testTenant, p.ID, context.Context.Err)
	assertRTBHErrorCode(t, err, "review_changed")
	assertRTBHErrorCode(t, approve(context.Context.Err), "review_changed")
	f.source.scope = previousScope
	withdrawn := errors.New("source permission withdrawn")
	if err := approve(func(context.Context) error { return withdrawn }); !errors.Is(err, withdrawn) {
		t.Fatal("approval ignored current source permission", err)
	}
	// The review is current while preparing the decision but reaches the exact
	// expiry boundary before the store's mutation callback can be invoked.
	f.source.beforePublish = func() { f.now = review.ExpiresAt }
	assertRTBHErrorCode(t, approve(context.Context.Err), "review_changed")
	got, err := f.store.Get(f.reviewer, testTenant, p.ID)
	if err != nil || got.State != rem.StateProposed || !slices.Equal(f.audit.actions(), []string{"remediation.propose"}) ||
		!slices.Equal(f.source.publications, []string{"remediation.propose"}) {
		t.Fatal("a refused review mutated the ledger", got, err, f.audit.actions(), f.source.publications)
	}
}
