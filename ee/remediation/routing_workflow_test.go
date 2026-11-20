// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
// Licensed under the probectl Commercial Source License. See ee/LICENSE.
// Production use requires a valid commercial agreement. Resale additionally
// requires an MSP entitlement and reseller agreement.

package remediation

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/crypto"
	rem "github.com/ctlplne/probectl/internal/remediation"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type routingWorkflowRecord struct {
	proposal rem.Proposal
	review   []byte
	handoff  rem.FlowSpecHandoff
	receipt  *rem.DiversionReceipt
	stopped  *time.Time
}

type routingWorkflowStore struct {
	*MemStore
	records map[string]*routingWorkflowRecord
}

func (s *routingWorkflowStore) owned(tenant, id string) (*routingWorkflowRecord, error) {
	record := s.records[id]
	if record == nil || record.proposal.TenantID != tenant {
		return nil, unavailableRTBHReview()
	}
	return record, nil
}

func (s *routingWorkflowStore) InsertFlowSpecAudited(ctx context.Context, tenant string, proposal rem.Proposal, review []byte,
	current rem.RTBHImpactPublication, sink AuditSink, event AuditEvent) (rem.Proposal, error) {
	id, err := crypto.UUIDv4()
	if err != nil {
		return rem.Proposal{}, err
	}
	proposal.ID, proposal.TenantID = id, tenant
	err = current.Publish(ctx, tenancy.Scope{Tenant: tenancy.ID(tenant)}, event.Actor, func(ctx context.Context, _ tenancy.Scope) error {
		if err := sink.Append(ctx, tenant, event.Actor, event.Action, id, event.Data); err != nil {
			return err
		}
		s.records[id] = &routingWorkflowRecord{proposal: proposal, review: bytes.Clone(review)}
		return nil
	})
	return proposal, err
}

func (s *routingWorkflowStore) LoadFlowSpecReview(_ context.Context, tenant, id string) (rem.Proposal, []byte, error) {
	stored, err := s.owned(tenant, id)
	if err != nil {
		return rem.Proposal{}, nil, err
	}
	return stored.proposal, bytes.Clone(stored.review), nil
}

func (s *routingWorkflowStore) ApproveFlowSpecAudited(ctx context.Context, tenant, id, actor, _ string, _ time.Time,
	expected, handoff []byte, current rem.RTBHImpactPublication, sink AuditSink, event AuditEvent) (rem.Proposal, error) {
	stored, err := s.owned(tenant, id)
	if err != nil || !bytes.Equal(stored.review, expected) {
		return rem.Proposal{}, changedRTBHReview()
	}
	compiled, err := decodeFlowSpecHandoff(id, handoff)
	if err != nil {
		return rem.Proposal{}, err
	}
	err = current.Publish(ctx, tenancy.Scope{Tenant: tenancy.ID(tenant)}, actor, func(ctx context.Context, _ tenancy.Scope) error {
		if err := sink.Append(ctx, tenant, actor, event.Action, id, event.Data); err != nil {
			return err
		}
		stored.proposal.State, stored.handoff = rem.StateApproved, compiled
		return nil
	})
	return stored.proposal, err
}

func (s *routingWorkflowStore) LoadFlowSpecHandoff(_ context.Context, tenant, id string) (rem.FlowSpecHandoff, error) {
	stored, err := s.owned(tenant, id)
	if err != nil || stored.handoff.ProposalID == "" {
		return rem.FlowSpecHandoff{}, unavailableRTBHReview()
	}
	return stored.handoff, nil
}

func (s *routingWorkflowStore) RequestFlowSpecWithdrawal(ctx context.Context, tenant, actor, id string, at time.Time,
	publication rem.RTBHImpactPublication, sink AuditSink) (rem.FlowSpecHandoff, error) {
	stored, err := s.owned(tenant, id)
	if err != nil {
		return rem.FlowSpecHandoff{}, err
	}
	err = publication.Publish(ctx, tenancy.Scope{Tenant: tenancy.ID(tenant)}, actor, func(ctx context.Context, _ tenancy.Scope) error {
		if err := sink.Append(ctx, tenant, actor, "remediation.flowspec.withdraw", id, nil); err != nil {
			return err
		}
		stored.handoff.WithdrawRequested = &at
		return nil
	})
	return stored.handoff, err
}

func (s *routingWorkflowStore) InsertDiversionAudited(ctx context.Context, tenant string, proposal rem.Proposal, review []byte,
	current rem.RTBHImpactPublication, sink AuditSink, event AuditEvent) (rem.Proposal, error) {
	return s.InsertFlowSpecAudited(ctx, tenant, proposal, review, current, sink, event)
}

func (s *routingWorkflowStore) ActiveDiversionStart(_ context.Context, tenant, id string) (rem.DiversionReceipt, error) {
	stored, err := s.owned(tenant, id)
	if err != nil || stored.receipt == nil || stored.stopped != nil || stored.receipt.Action != rem.DiversionStart {
		return rem.DiversionReceipt{}, unavailableRTBHReview()
	}
	return *stored.receipt, nil
}

func (s *routingWorkflowStore) loadDiversionReview(_ context.Context, tenant, id string) (loadedDiversionReview, error) {
	stored, err := s.owned(tenant, id)
	if err != nil {
		return loadedDiversionReview{}, err
	}
	return loadedDiversionReview{Proposal: stored.proposal, Raw: bytes.Clone(stored.review), Receipt: stored.receipt, StartStoppedAt: stored.stopped}, nil
}

func (s *routingWorkflowStore) ApproveDiversionAudited(ctx context.Context, tenant, id, actor, _ string, at time.Time, expected []byte,
	candidate rem.DiversionPreview, current rem.RTBHImpactPublication, sink AuditSink, event AuditEvent) (rem.DiversionReceipt, error) {
	stored, err := s.owned(tenant, id)
	if err != nil || !bytes.Equal(stored.review, expected) {
		return rem.DiversionReceipt{}, changedRTBHReview()
	}
	receipt := rem.DiversionReceipt{Connector: rem.LocalDiversionPreview, Action: candidate.Action, Prefix: candidate.Prefix, StartPreviewID: id, RecordedAt: at}
	err = current.Publish(ctx, tenancy.Scope{Tenant: tenancy.ID(tenant)}, actor, func(ctx context.Context, _ tenancy.Scope) error {
		if err := sink.Append(ctx, tenant, actor, event.Action, id, event.Data); err != nil {
			return err
		}
		if candidate.Action == rem.DiversionStop {
			receipt.StartPreviewID = candidate.StartPreviewID
			start, err := s.owned(tenant, candidate.StartPreviewID)
			if err != nil {
				return err
			}
			start.stopped = &at
		}
		stored.proposal.State, stored.receipt = rem.StateApproved, &receipt
		return nil
	})
	return receipt, err
}

type routingWorkflowSource struct {
	tenant   string
	impact   rem.PrefixImpact
	mismatch bool
}

func (f *routingWorkflowSource) ObservePrefixImpact(ctx context.Context, tenant string, input rem.PrefixImpactInput, credential func(context.Context) error) (rem.PrefixImpact, error) {
	prepared, err := f.PreparePrefixImpact(ctx, tenant, input, time.Time{}, credential)
	return prepared.Impact, err
}

func (f *routingWorkflowSource) PreparePrefixImpact(ctx context.Context, tenant string, _ rem.PrefixImpactInput, end time.Time, credential func(context.Context) error) (rem.RTBHImpactPublication, error) {
	if tenant != f.tenant || !end.IsZero() && !f.impact.To.Equal(end) {
		return rem.RTBHImpactPublication{}, unavailableRTBHReview()
	}
	if err := credential(ctx); err != nil {
		return rem.RTBHImpactPublication{}, err
	}
	digest := strings.Repeat("a", 64)
	if f.mismatch {
		digest = strings.Repeat("b", 64)
	}
	return rem.RTBHImpactPublication{Scope: digest, Impact: f.impact, WholeScope: &f.impact,
		Publish: func(ctx context.Context, scope tenancy.Scope, _ string, mutation func(context.Context, tenancy.Scope) error) error {
			if scope.Tenant.String() != f.tenant {
				return unavailableRTBHReview()
			}
			return mutation(ctx, scope)
		},
	}, nil
}

func (f *routingWorkflowSource) PrepareFlowSpecImpact(ctx context.Context, tenant string, input rem.PrefixImpactInput,
	_ rem.FlowSpecTransport, end time.Time, credential func(context.Context) error) (rem.RTBHImpactPublication, error) {
	return f.PreparePrefixImpact(ctx, tenant, input, end, credential)
}

type routingWorkflowFixture struct {
	service                     *Service
	source                      *routingWorkflowSource
	proposer, reviewer, sibling context.Context
	clock                       *time.Time
	tenant                      string
	audits                      *[]AuditEvent
}

func newRoutingWorkflowFixture(t *testing.T) routingWorkflowFixture {
	t.Helper()
	tenant := "owned-routing"
	at := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	source := &routingWorkflowSource{tenant: tenant, impact: rem.PrefixImpact{
		Prefix: "192.0.2.0/26", From: at.Add(-2 * time.Minute), To: at.Add(-time.Minute),
		ObservedRecords: 2, ObservedAddresses: 1, Matched: rem.PrefixTraffic{Bytes: "200", Packets: "2"},
		KnownBenign: rem.PrefixTraffic{Bytes: "25", Packets: "1"}, Unclassified: rem.PrefixTraffic{Bytes: "175", Packets: "1"},
	}}
	var audits []AuditEvent
	log := Audit(func(_ context.Context, actualTenant, actor, action, target string, data map[string]any) error {
		if actualTenant != tenant || actor == "" || target == "" {
			t.Fatal("routing workflow audit lost scope", actualTenant, actor, action)
		}
		audits = append(audits, AuditEvent{Actor: actor, Action: action, Target: target, Data: data})
		return nil
	})
	selected := &routingWorkflowStore{MemStore: NewMemStore(), records: map[string]*routingWorkflowRecord{}}
	return routingWorkflowFixture{
		service: New(selected, nil, log, Config{ApprovalsEnabled: true, MaxBlastRadius: 64, PrefixImpact: source}).withNow(func() time.Time { return at }),
		source:  source, tenant: tenant, clock: &at, audits: &audits,
		proposer: remediationTestActor(t.Context(), tenant, "11111111-1111-4111-8111-111111111111"),
		reviewer: remediationTestActor(t.Context(), tenant, "22222222-2222-4222-8222-222222222222"),
		sibling:  remediationTestActor(t.Context(), "sibling-routing", "22222222-2222-4222-8222-222222222222"),
	}
}

func TestFlowSpecReviewPreservesCurrentApprovalExpiryAndWithdrawal(t *testing.T) {
	f := newRoutingWorkflowFixture(t)
	check := func(context.Context) error { return nil }
	port := uint16(18443)
	selection := rem.FlowSpecPreviewInput{RoutingPolicyAgreed: true, Transport: rem.FlowSpecTransport{Protocol: "tcp", DestinationPort: &port}}
	preview, err := f.service.PreviewFlowSpec(f.proposer, f.tenant, selection, check)
	if err != nil || preview.Matching != f.source.impact || preview.WholeScope != f.source.impact {
		t.Fatal("the preview did not retain the scoped originals", preview, err)
	}
	proposal, err := f.service.ProposeFlowSpec(f.proposer, f.tenant, "proposer", rem.FlowSpecProposalInput{
		Preview: selection, ObservedTo: preview.Matching.To, PreviewFingerprint: preview.Fingerprint, MaxKnownBenignPackets: "1",
	}, check)
	if err != nil || proposal.State != rem.StateProposed || proposal.DryRun.BlastRadius != 64 {
		t.Fatal("the exact reviewed preview did not become a pending proposal", proposal, err)
	}
	f.source.mismatch = true
	if _, err := f.service.GetFlowSpecReview(f.reviewer, f.tenant, proposal.ID, check); err == nil {
		t.Fatal("changed retained source was accepted")
	}
	f.source.mismatch = false
	if _, err := f.service.GetFlowSpecReview(f.sibling, "sibling-routing", proposal.ID, check); err == nil {
		t.Fatal("a sibling reviewer read the proposal")
	}
	review, err := f.service.GetFlowSpecReview(f.reviewer, f.tenant, proposal.ID, check)
	if err != nil {
		t.Fatal(err)
	}
	entries := uint32(1)
	router := rem.FlowSpecQualificationInput{Profile: rem.FlowSpecFRR1071, RoutingTable: "default", AvailableEntries: &entries}
	qualification, err := f.service.QualifyFlowSpec(f.reviewer, f.tenant, proposal.ID, router, check)
	if err != nil || qualification.QualificationFingerprint == "" {
		t.Fatal("the measured candidate was not qualified", err)
	}
	handoff := &rem.FlowSpecHandoffInput{Qualification: router, QualificationFingerprint: qualification.QualificationFingerprint, DurationSeconds: 2}
	approval := rem.FlowSpecApprovalInput{Fingerprint: review.Fingerprint, Handoff: handoff}
	if _, err := f.service.ApproveFlowSpec(f.proposer, f.tenant, "same user", proposal.ID, approval, check); !errors.Is(err, rem.ErrSelfApproval) {
		t.Fatal("same member authorized the handoff", err)
	}
	handoff.DurationSeconds = 0
	if _, err := f.service.ApproveFlowSpec(f.reviewer, f.tenant, "reviewer", proposal.ID, approval, check); err == nil {
		t.Fatal("zero-duration handoff was accepted")
	}
	handoff.DurationSeconds = 2
	approved, err := f.service.ApproveFlowSpec(f.reviewer, f.tenant, "reviewer", proposal.ID, approval, check)
	if err != nil || approved.State != rem.StateApproved {
		t.Fatal("independent approval lost the qualified handoff", approved, err)
	}
	status, err := f.service.GetFlowSpecHandoff(f.reviewer, f.tenant, proposal.ID, check)
	if err != nil || status.State != rem.FlowSpecAuthorized || !status.ExpiresAt.Equal(f.clock.Add(2*time.Second)) {
		t.Fatal("handoff lost its exact expiry", status, err)
	}
	*f.clock = status.ExpiresAt
	expired, err := f.service.GetFlowSpecHandoff(f.reviewer, f.tenant, proposal.ID, check)
	if err != nil || expired.State != rem.FlowSpecExpired {
		t.Fatal("handoff remained authorized after its expiry", expired, err)
	}
	authority, err := f.source.PreparePrefixImpact(f.reviewer, f.tenant, selection.PrefixImpactInput, time.Time{}, check)
	if err != nil {
		t.Fatal(err)
	}
	withdrawn, err := f.service.WithdrawFlowSpecHandoff(f.reviewer, f.tenant, "reviewer", proposal.ID, authority)
	if err != nil || withdrawn.State != rem.FlowSpecWithdrawalRequested || len(*f.audits) != 4 {
		t.Fatal("withdrawal intent lost the audit trail", withdrawn, err, *f.audits)
	}
}

func TestDiversionReviewRequiresIndependentLocalStartAndStop(t *testing.T) {
	f := newRoutingWorkflowFixture(t)
	check := func(context.Context) error { return nil }
	input := rem.PrefixImpactInput{}
	authority, err := f.source.PreparePrefixImpact(f.proposer, f.tenant, input, time.Time{}, check)
	if err != nil {
		t.Fatal(err)
	}
	selection := rem.DiversionPreviewInput{Action: rem.DiversionStart, Observation: &input}
	start := approveLocalWorkflow(t, f, selection, authority)
	if start.Connector != rem.LocalDiversionPreview || start.Action != rem.DiversionStart || start.Prefix != f.source.impact.Prefix {
		t.Fatal("the approval did not return the expected local receipt", start)
	}
	stop := approveLocalWorkflow(t, f, rem.DiversionPreviewInput{Action: rem.DiversionStop, StartPreviewID: start.StartPreviewID}, authority)
	if stop.Action != rem.DiversionStop || stop.StartPreviewID != start.StartPreviewID || len(*f.audits) != 6 {
		t.Fatal("the local stop lost its exact start or audit trail", stop, *f.audits)
	}
	if _, err := f.service.PreviewDiversion(f.reviewer, f.tenant, rem.DiversionPreviewInput{
		Action: rem.DiversionStop, StartPreviewID: start.StartPreviewID,
	}, check); err == nil {
		t.Fatal("a stopped local preview was still active")
	}
}

func approveLocalWorkflow(t *testing.T, f routingWorkflowFixture, selection rem.DiversionPreviewInput, authority rem.RTBHImpactPublication) rem.DiversionReceipt {
	t.Helper()
	check := func(context.Context) error { return nil }
	preview, err := f.service.PreviewDiversion(f.proposer, f.tenant, selection, check)
	if err != nil {
		t.Fatal(err)
	}
	input := rem.DiversionProposalInput{Selection: selection, PreviewFingerprint: preview.Fingerprint}
	if preview.Impact != nil {
		input.ObservedTo = &preview.Impact.To
		input.MaxKnownBenignPackets = "1"
	}
	proposal, err := f.service.ProposeDiversion(f.proposer, f.tenant, "proposer", input, check, authority)
	if err != nil || proposal.State != rem.StateProposed {
		t.Fatal("preview was not filed for independent approval", proposal, err)
	}
	if _, err := f.service.GetDiversionReview(f.sibling, "sibling-routing", proposal.ID, check); err == nil {
		t.Fatal("a sibling reviewer read the preview")
	}
	review, err := f.service.GetDiversionReview(f.reviewer, f.tenant, proposal.ID, check)
	if err != nil || review.Receipt != nil {
		t.Fatal("a pending preview exposed a receipt or became unreadable", review, err)
	}
	approval := rem.DiversionApprovalInput{Fingerprint: review.Fingerprint}
	if _, err := f.service.ApproveDiversion(f.proposer, f.tenant, "same user", proposal.ID, approval, check, authority); !errors.Is(err, rem.ErrSelfApproval) {
		t.Fatal("same member approved the local preview", err)
	}
	recorded, err := f.service.ApproveDiversion(f.reviewer, f.tenant, "reviewer", proposal.ID, approval, check, authority)
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := f.service.ApproveDiversion(f.reviewer, f.tenant, "same reviewer", proposal.ID, approval, check, authority)
	if err != nil || replayed != recorded {
		t.Fatal("a retry lost the exact recorded preview", replayed, err)
	}
	return recorded
}
