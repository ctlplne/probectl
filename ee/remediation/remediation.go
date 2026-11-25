// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License; see ee/LICENSE.
// Production use requires a valid commercial agreement; resale additionally
// requires an MSP entitlement and reseller agreement.

// Package remediation (ee/) implements the guarded-remediation workflow
// (S-EE5, F44 — guardrail-critical), unlocked by the `remediation` Enterprise
// feature. It implements the CORE internal/remediation.Service seam. The
// ratified policy is enforced HERE: probectl NEVER executes (there is no
// executor); approval is a recorded, audited, human-only, blast-radius-limited,
// advisory-only-by-default sign-off. See internal/remediation for the policy.
package remediation

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/auth"
	rem "github.com/ctlplne/probectl/internal/remediation"
)

// Audit adapts a function to AuditSink. Unit tests use it to inject success and
// failure; production uses NewTenantAudit so PostgreSQL can append inside the
// same tenant transaction as the remediation mutation.
type Audit func(ctx context.Context, tenantID, actor, action, target string, data map[string]any) error

// Append implements AuditSink.
func (a Audit) Append(ctx context.Context, tenantID, actor, action, target string, data map[string]any) error {
	if a == nil {
		return errAuditUnavailable
	}
	return a(ctx, tenantID, actor, action, target, data)
}

// AuditSink appends a tamper-evident entry to the tenant's audit stream.
// Mutation stores require the production sink's transaction-bound extension;
// an audit failure must leave the remediation mutation unpublished.
type AuditSink interface {
	Append(ctx context.Context, tenantID, actor, action, target string, data map[string]any) error
}

var errAuditUnavailable = errors.New("remediation: mandatory audit sink is unavailable")

// Service is the ee implementation of internal/remediation.Service.
type Service struct {
	store        Store
	estimator    rem.Estimator
	audit        AuditSink
	prefixImpact rem.PrefixImpactSource

	approvalsEnabled bool
	maxBlastRadius   int
	now              func() time.Time
}

// Config wires the policy parameters (from config).
type Config struct {
	ApprovalsEnabled bool // the advisory-only master switch (default false)
	MaxBlastRadius   int  // approvable blast-radius ceiling
	PrefixImpact     rem.PrefixImpactSource
}

// New builds the service. estimator computes the dry-run blast radius (a
// read-only topology what-if); audit records the decision trail.
func New(store Store, estimator rem.Estimator, audit AuditSink, cfg Config) *Service {
	if cfg.MaxBlastRadius <= 0 {
		cfg.MaxBlastRadius = 50
	}
	return &Service{
		store: store, estimator: estimator, audit: audit, prefixImpact: cfg.PrefixImpact,
		approvalsEnabled: cfg.ApprovalsEnabled, maxBlastRadius: cfg.MaxBlastRadius,
		now: time.Now,
	}
}

// withNow injects a clock (tests).
func (s *Service) withNow(now func() time.Time) *Service { s.now = now; return s }

// ApprovalsEnabled reports the advisory-only master switch.
func (s *Service) ApprovalsEnabled() bool { return s.approvalsEnabled }

// remediationActor separates the stable tenant member from the display label.
func remediationActor(ctx context.Context, tenantID string, interactive bool) (string, error) {
	if _, err := remediationTenantContext(ctx, tenantID); err != nil {
		return "", err
	}
	actor := auth.PrincipalFrom(ctx)
	if actor == nil || actor.TenantID != tenantID || interactive && actor.ViaBearerToken {
		return "", rem.ErrApprovalActorUnavailable
	}
	id, err := uuid.Parse(actor.UserID)
	if err != nil || id == uuid.Nil || id.String() != actor.UserID {
		return "", rem.ErrApprovalActorUnavailable
	}
	return id.String(), nil
}

// Propose files a PROPOSED proposal and runs the dry-run. It NEVER approves —
// whatever the caller (including the proposal-only MCP tool fed by ingested
// data), the result is always state=proposed awaiting a human.
func (s *Service) Propose(ctx context.Context, tenantID, proposedBy string, in rem.ProposeInput) (rem.Proposal, error) {
	in.Title = strings.TrimSpace(in.Title)
	if !rem.ValidKind(in.Kind) {
		return rem.Proposal{}, rem.Error{Code: "validation", Message: "unknown remediation kind"}
	}
	if in.Title == "" {
		return rem.Proposal{}, rem.Error{Code: "validation", Message: "title is required"}
	}
	userID, err := remediationActor(ctx, tenantID, false)
	if err != nil {
		return rem.Proposal{}, err
	}
	// The dry-run is a read-only topology simulation — it EXECUTES NOTHING.
	dry := rem.DryRun{Note: "no target to simulate"}
	switch {
	case in.Target != "":
		if s.estimator != nil {
			dry = s.estimator.Estimate(ctx, tenantID, in.Target)
		}
	case rem.KindRequiresTarget(in.Kind):
		// AUD-18: a network-changing kind (reroute/traffic-shift) with no target
		// is NOT simulatable, so its blast radius is UNKNOWN — mark it so the
		// Approve guard fails closed. Otherwise omitting the target would leave
		// BlastRadius at the zero value and silently bypass the
		// "unknown blast radius blocks approval" rule. Benign kinds (open_ticket,
		// trustctl_renewal) carry no network blast radius, so no target is fine.
		dry = rem.DryRun{BlastRadius: -1, Note: noteUnknown}
	}
	p := rem.Proposal{
		TenantID:       tenantID,
		Kind:           in.Kind,
		Title:          in.Title,
		Rationale:      in.Rationale,
		Target:         in.Target,
		IncidentID:     in.IncidentID,
		DryRun:         dry,
		State:          rem.StateProposed, // ALWAYS proposed — never approved on creation
		ProposedBy:     proposedBy,
		ProposedUserID: userID,
		CreatedAt:      s.now().UTC(),
	}
	saved, err := s.store.InsertAudited(ctx, tenantID, p, s.audit, AuditEvent{
		Actor: proposedBy, Action: "remediation.propose",
		Data: map[string]any{
			"kind": p.Kind, "target": p.Target, "blast_radius": p.DryRun.BlastRadius, "proposer_user_id": userID,
		},
	})
	if err != nil {
		return rem.Proposal{}, err
	}
	return saved, nil
}

// List returns the tenant's proposals (newest first).
func (s *Service) List(ctx context.Context, tenantID string) ([]rem.Proposal, error) {
	return s.store.List(ctx, tenantID)
}

// Get returns one proposal.
func (s *Service) Get(ctx context.Context, tenantID, id string) (rem.Proposal, error) {
	return s.store.Get(ctx, tenantID, id)
}

// Approve records a human's authorization — and ONLY records it. It fails
// closed when approvals are disabled (advisory-only), when the proposal is not
// in the proposed state, when the blast radius is unknown, or when it exceeds
// the limit. probectl executes NOTHING here.
func (s *Service) Approve(ctx context.Context, tenantID, approver, id, note string) (rem.Proposal, error) {
	if !s.approvalsEnabled {
		return rem.Proposal{}, rem.ErrApprovalsDisabled // the master switch is off
	}
	p, err := s.store.Get(ctx, tenantID, id)
	if err != nil {
		return rem.Proposal{}, err
	}
	if p.State != rem.StateProposed {
		return rem.Proposal{}, rem.ErrNotProposed
	}
	if p.Kind == rem.KindRTBHReview || p.Kind == rem.KindFlowSpecReview || p.Kind == rem.KindDiversionPreview || p.Kind == rem.KindRoutingTransferReview {
		return rem.Proposal{}, rem.Error{Code: "validation", Message: "approve this proposal from its exact routing review"}
	}
	userID, err := remediationActor(ctx, tenantID, true)
	if err != nil {
		return rem.Proposal{}, err
	}
	// Four-eyes (docs/guardrails.md G7-8) uses the original account. Older
	// display-only proposals need a new proposal with a verified actor.
	if p.ProposedUserID == "" {
		if err := s.record(ctx, tenantID, approver, "remediation.approve_blocked", id, map[string]any{
			"reason": "proposer_identity_unavailable", "approver_user_id": userID,
		}); err != nil {
			return rem.Proposal{}, err
		}
		return rem.Proposal{}, rem.ErrProposerIdentityUnavailable
	}
	if userID == p.ProposedUserID {
		if err := s.record(ctx, tenantID, approver, "remediation.approve_blocked", id, map[string]any{
			"reason": "self_approval", "proposed_by": p.ProposedBy, "approver_user_id": userID,
		}); err != nil {
			return rem.Proposal{}, err
		}
		return rem.Proposal{}, rem.ErrSelfApproval
	}
	// Blast-radius guard (fail closed): an unknown or over-limit radius blocks
	// approval. The audit records the BLOCKED attempt either way.
	if p.DryRun.BlastRadius < 0 || p.DryRun.Note == noteUnknown {
		if err := s.record(ctx, tenantID, approver, "remediation.approve_blocked", id, map[string]any{"reason": "blast_radius_unknown"}); err != nil {
			return rem.Proposal{}, err
		}
		return rem.Proposal{}, rem.ErrUnknownBlastRadius
	}
	if p.DryRun.BlastRadius > s.maxBlastRadius {
		if err := s.record(ctx, tenantID, approver, "remediation.approve_blocked", id, map[string]any{
			"reason": "blast_radius_exceeded", "blast_radius": p.DryRun.BlastRadius, "limit": s.maxBlastRadius,
		}); err != nil {
			return rem.Proposal{}, err
		}
		return rem.Proposal{}, rem.ErrBlastRadiusExceeded
	}
	return s.decide(ctx, tenantID, approver, id, note, rem.StateApproved, "remediation.approve")
}

// Reject records a human's decline (audited).
func (s *Service) Reject(ctx context.Context, tenantID, decider, id, note string) (rem.Proposal, error) {
	p, err := s.store.Get(ctx, tenantID, id)
	if err != nil {
		return rem.Proposal{}, err
	}
	if p.State != rem.StateProposed {
		return rem.Proposal{}, rem.ErrNotProposed
	}
	return s.decide(ctx, tenantID, decider, id, note, rem.StateRejected, "remediation.reject")
}

func (s *Service) decide(ctx context.Context, tenantID, actor, id, note string, state rem.State, action string) (rem.Proposal, error) {
	at := s.now().UTC()
	updated, err := s.store.DecideAudited(ctx, tenantID, id, state, actor, note, at, s.audit, AuditEvent{
		Actor: actor, Action: action, Target: id,
		Data: map[string]any{"state": state, "note": note},
	})
	if err != nil {
		return rem.Proposal{}, err
	}
	return updated, nil
}

func (s *Service) record(ctx context.Context, tenantID, actor, action, target string, data map[string]any) error {
	if s.audit == nil {
		return errAuditUnavailable
	}
	return s.audit.Append(ctx, tenantID, actor, action, target, data)
}

const noteUnknown = "topology unavailable — blast radius unknown"
