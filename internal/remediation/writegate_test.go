// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package remediation

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/license"
)

type remediationDelegateSpy struct {
	proposeCalls []string
	listCalls    []string
	getCalls     []string
	approveCalls []string
	rejectCalls  []string
}

type rtbhPreviewDelegate struct {
	remediationDelegateSpy
	tenant string
	input  RTBHPreviewInput
}

type rtbhReviewDelegate struct {
	remediationDelegateSpy
	proposed    RTBHProposalInput
	proposalFor []string
	reviewFor   []string
	approvalFor []string
}

func (s *rtbhReviewDelegate) ProposeRTBH(ctx context.Context, tenant, actor string, input RTBHProposalInput, check func(context.Context) error) (Proposal, error) {
	s.proposalFor = []string{tenant, actor}
	s.proposed = input
	return Proposal{ID: "proposal", TenantID: tenant, State: StateProposed}, check(ctx)
}

func (s *rtbhReviewDelegate) GetRTBHReview(ctx context.Context, tenant, id string, check func(context.Context) error) (RTBHReview, error) {
	s.reviewFor = []string{tenant, id}
	return RTBHReview{Fingerprint: "displayed-review"}, check(ctx)
}

func (s *rtbhReviewDelegate) ApproveRTBH(ctx context.Context, tenant, actor, id, fingerprint, note string, check func(context.Context) error) (Proposal, error) {
	s.approvalFor = []string{tenant, actor, id, fingerprint, note}
	return Proposal{ID: id, TenantID: tenant, State: StateApproved}, check(ctx)
}

func TestRTBHReviewLicenseGate(t *testing.T) {
	input := RTBHProposalInput{PreviewFingerprint: "displayed-preview", MaxKnownBenignPackets: "9007199254740993"}
	for _, tc := range []struct {
		name      string
		writes    bool
		supported bool
		wantCalls int
	}{
		{name: "retains scope and authority", writes: true, supported: true, wantCalls: 3},
		{name: "recalled review remains readable", supported: true, wantCalls: 1},
		{name: "unavailable delegate", writes: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := t.Context()
			checks := 0
			verify := func(got context.Context) error {
				if got != ctx {
					t.Fatal("the authority check received a different context")
				}
				checks++
				return nil
			}
			spy := &rtbhReviewDelegate{}
			var delegate Service = &spy.remediationDelegateSpy
			if tc.supported {
				delegate = spy
			}
			service := GateServiceWrites(delegate, license.WriteCapability(func() bool { return tc.writes })).(RTBHReviews)
			proposed, proposeErr := service.ProposeRTBH(ctx, "tenant-a", "proposer", input, verify)
			review, readErr := service.GetRTBHReview(ctx, "tenant-a", "proposal", verify)
			approved, approveErr := service.ApproveRTBH(ctx, "tenant-a", "reviewer", "proposal", review.Fingerprint, "approved in review", verify)
			if checks != tc.wantCalls {
				t.Fatalf("authority checks = %d, want %d", checks, tc.wantCalls)
			}
			if !tc.supported {
				var unavailable Error
				for _, err := range []error{proposeErr, readErr, approveErr} {
					if !errors.As(err, &unavailable) || unavailable.Code != "not_found" {
						t.Fatal("missing review delegate must fail closed", err)
					}
				}
				return
			}
			if readErr != nil || review.Fingerprint != "displayed-review" || !slices.Equal(spy.reviewFor, []string{"tenant-a", "proposal"}) {
				t.Fatal("the readable review lost its scope, fingerprint, or authority result", review, readErr, spy.reviewFor)
			}
			denied := errors.New("current authority withdrawn")
			if _, err := service.GetRTBHReview(ctx, "tenant-a", "proposal", func(context.Context) error { return denied }); !errors.Is(err, denied) {
				t.Fatal("the authority failure was lost", err)
			}
			if !tc.writes {
				if !errors.Is(proposeErr, license.ErrReadOnly) || !errors.Is(approveErr, license.ErrReadOnly) || spy.proposalFor != nil || spy.approvalFor != nil {
					t.Fatal("a read-only mutation reached the delegate", proposeErr, approveErr, spy.proposalFor, spy.approvalFor)
				}
				return
			}
			if proposeErr != nil || proposed.State != StateProposed || spy.proposed != input || !slices.Equal(spy.proposalFor, []string{"tenant-a", "proposer"}) {
				t.Fatal("the proposal lost its input or authority result", proposed, proposeErr, spy.proposalFor)
			}
			if approveErr != nil || approved.State != StateApproved || !slices.Equal(spy.approvalFor, []string{"tenant-a", "reviewer", "proposal", "displayed-review", "approved in review"}) {
				t.Fatal("the approval lost its identity, fingerprint, note, or authority result", approved, approveErr, spy.approvalFor)
			}
		})
	}
}

func (s *rtbhPreviewDelegate) PreviewRTBH(ctx context.Context, tenant string, input RTBHPreviewInput, check func(context.Context) error) (RTBHPreview, error) {
	s.tenant, s.input = tenant, input
	if err := check(ctx); err != nil {
		return RTBHPreview{}, err
	}
	return RTBHPreview{Impact: PrefixImpact{Matched: PrefixTraffic{Bytes: "9007199254740993", Packets: "1"}}}, nil
}

func TestRTBHPreviewPreservesReadOnlyScopeAndAuthority(t *testing.T) {
	readOnly := license.WriteCapability(func() bool { return false })
	if GateServiceWrites(nil, readOnly) != nil {
		t.Fatal("the write gate exposed an unavailable service")
	}
	const tenant = "tenant-a"
	input := RTBHPreviewInput{PrefixImpactInput: PrefixImpactInput{WholeViewID: "owned-view"}}
	for _, supported := range []bool{false, true} {
		spy := &rtbhPreviewDelegate{}
		var delegate Service = &spy.remediationDelegateSpy
		if supported {
			delegate = spy
		}
		preview := GateServiceWrites(delegate, readOnly).(RTBHPreviewer)
		checks := 0
		result, err := preview.PreviewRTBH(t.Context(), tenant, input, func(context.Context) error { checks++; return nil })
		if !supported {
			var domain Error
			if !errors.As(err, &domain) || domain.Code != "not_found" || checks != 0 {
				t.Fatal("the gate exposed unavailable preview authority", err, checks)
			}
			continue
		}
		if err != nil || checks != 1 || spy.input != input || spy.tenant != tenant || result.Impact.Matched.Bytes != "9007199254740993" {
			t.Fatal("the read-only gate lost the preview authority or exact result", result, err, spy.tenant, checks)
		}
		refused := errors.New("current source grant withdrawn")
		result, err = preview.PreviewRTBH(t.Context(), tenant, input, func(context.Context) error { return refused })
		if !errors.Is(err, refused) || result != (RTBHPreview{}) {
			t.Fatal("the preview escaped the current authority check", result, err)
		}
	}
}

func (s *remediationDelegateSpy) Propose(_ context.Context, tenantID, _ string, in ProposeInput) (Proposal, error) {
	s.proposeCalls = append(s.proposeCalls, tenantID)
	return Proposal{ID: "proposal-" + tenantID, TenantID: tenantID, Kind: in.Kind, State: StateProposed}, nil
}

func (s *remediationDelegateSpy) List(_ context.Context, tenantID string) ([]Proposal, error) {
	s.listCalls = append(s.listCalls, tenantID)
	return []Proposal{{ID: "proposal-" + tenantID, TenantID: tenantID, State: StateProposed}}, nil
}

func (s *remediationDelegateSpy) Get(_ context.Context, tenantID, id string) (Proposal, error) {
	s.getCalls = append(s.getCalls, tenantID)
	return Proposal{ID: id, TenantID: tenantID, State: StateProposed}, nil
}

func (s *remediationDelegateSpy) Approve(_ context.Context, tenantID, _, id, _ string) (Proposal, error) {
	s.approveCalls = append(s.approveCalls, tenantID)
	return Proposal{ID: id, TenantID: tenantID, State: StateApproved}, nil
}

func (s *remediationDelegateSpy) Reject(_ context.Context, tenantID, _, id, _ string) (Proposal, error) {
	s.rejectCalls = append(s.rejectCalls, tenantID)
	return Proposal{ID: id, TenantID: tenantID, State: StateRejected}, nil
}

func (*remediationDelegateSpy) ApprovalsEnabled() bool { return true }

func TestLicenseReadOnlyRemediationMutationGateClockAdvancedDelegateSpy(t *testing.T) {
	readOnlyAt := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	now := readOnlyAt.Add(-time.Second)
	spy := &remediationDelegateSpy{}
	service := GateServiceWrites(spy, license.WriteCapability(func() bool {
		return now.Before(readOnlyAt)
	}))
	ctx := context.Background()
	tenants := []string{"tenant-a", "tenant-b"}

	for _, tenantID := range tenants {
		proposal, err := service.Propose(ctx, tenantID, "user:admin@example.test", ProposeInput{
			Kind: KindOpenTicket, Title: "inspect",
		})
		if err != nil {
			t.Fatalf("active propose for %s: %v", tenantID, err)
		}
		if _, err := service.Approve(ctx, tenantID, "user:admin@example.test", proposal.ID, "go"); err != nil {
			t.Fatalf("active approve for %s: %v", tenantID, err)
		}
		if _, err := service.Reject(ctx, tenantID, "user:admin@example.test", proposal.ID, "stop"); err != nil {
			t.Fatalf("active reject for %s: %v", tenantID, err)
		}
	}

	now = readOnlyAt
	for _, tenantID := range tenants {
		if _, err := service.List(ctx, tenantID); err != nil {
			t.Fatalf("read-only list for %s: %v", tenantID, err)
		}
		if _, err := service.Get(ctx, tenantID, "proposal-"+tenantID); err != nil {
			t.Fatalf("read-only get for %s: %v", tenantID, err)
		}
		mutations := []struct {
			name string
			call func() error
		}{
			{"propose", func() error {
				_, err := service.Propose(ctx, tenantID, "user:admin@example.test", ProposeInput{Kind: KindOpenTicket, Title: "blocked"})
				return err
			}},
			{"approve", func() error {
				_, err := service.Approve(ctx, tenantID, "user:admin@example.test", "proposal-"+tenantID, "blocked")
				return err
			}},
			{"reject", func() error {
				_, err := service.Reject(ctx, tenantID, "user:admin@example.test", "proposal-"+tenantID, "blocked")
				return err
			}},
		}
		for _, mutation := range mutations {
			if err := mutation.call(); !errors.Is(err, license.ErrReadOnly) {
				t.Fatalf("read-only %s for %s = %v, want ErrReadOnly", mutation.name, tenantID, err)
			}
		}
	}

	if len(spy.proposeCalls) != len(tenants) ||
		len(spy.approveCalls) != len(tenants) ||
		len(spy.rejectCalls) != len(tenants) {
		t.Fatalf("read-only mutation reached delegate: propose=%v approve=%v reject=%v",
			spy.proposeCalls, spy.approveCalls, spy.rejectCalls)
	}
	if len(spy.listCalls) != len(tenants) || len(spy.getCalls) != len(tenants) {
		t.Fatalf("read-only reads did not reach delegate: list=%v get=%v", spy.listCalls, spy.getCalls)
	}
	if !service.ApprovalsEnabled() {
		t.Fatal("read-only surface must preserve the delegate's readable approval configuration")
	}
}
