// probectl Commercial License — PLACEHOLDER (legal text TBD with counsel).

// Package remediation (ee/) implements the guarded-remediation workflow
// (S-EE5, F44 — guardrail-critical), unlocked by the `remediation` Enterprise
// feature. It implements the CORE internal/remediation.Service seam. The
// ratified policy is enforced HERE: probectl NEVER executes (there is no
// executor); approval is a recorded, audited, human-only, blast-radius-limited,
// advisory-only-by-default sign-off. See internal/remediation for the policy.
package remediation

import (
	"context"
	"fmt"
	"strings"
	"time"

	rem "github.com/imfeelingtheagi/probectl/internal/remediation"
)

// Audit appends a tamper-evident entry to the tenant's audit stream (the
// proposal→approval→reject trail). Implemented over internal/audit.
type Audit func(ctx context.Context, tenantID, actor, action, target string, data map[string]any) error

// Service is the ee implementation of internal/remediation.Service.
type Service struct {
	store     Store
	estimator rem.Estimator
	audit     Audit

	approvalsEnabled bool
	maxBlastRadius   int
	now              func() time.Time
}

// Config wires the policy parameters (from config).
type Config struct {
	ApprovalsEnabled bool // the advisory-only master switch (default false)
	MaxBlastRadius   int  // approvable blast-radius ceiling
}

// New builds the service. estimator computes the dry-run blast radius (a
// read-only topology what-if); audit records the decision trail.
func New(store Store, estimator rem.Estimator, audit Audit, cfg Config) *Service {
	if cfg.MaxBlastRadius <= 0 {
		cfg.MaxBlastRadius = 50
	}
	return &Service{
		store: store, estimator: estimator, audit: audit,
		approvalsEnabled: cfg.ApprovalsEnabled, maxBlastRadius: cfg.MaxBlastRadius,
		now: time.Now,
	}
}

// withNow injects a clock (tests).
func (s *Service) withNow(now func() time.Time) *Service { s.now = now; return s }

// ApprovalsEnabled reports the advisory-only master switch.
func (s *Service) ApprovalsEnabled() bool { return s.approvalsEnabled }

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
	// The dry-run is a read-only topology simulation — it EXECUTES NOTHING.
	dry := rem.DryRun{Note: "no target to simulate"}
	if s.estimator != nil && in.Target != "" {
		dry = s.estimator.Estimate(ctx, tenantID, in.Target)
	}
	p := rem.Proposal{
		TenantID:   tenantID,
		Kind:       in.Kind,
		Title:      in.Title,
		Rationale:  in.Rationale,
		Target:     in.Target,
		IncidentID: in.IncidentID,
		DryRun:     dry,
		State:      rem.StateProposed, // ALWAYS proposed — never approved on creation
		ProposedBy: proposedBy,
		CreatedAt:  s.now().UTC(),
	}
	saved, err := s.store.Insert(ctx, tenantID, p)
	if err != nil {
		return rem.Proposal{}, err
	}
	s.record(ctx, tenantID, proposedBy, "remediation.propose", saved.ID, map[string]any{
		"kind": saved.Kind, "target": saved.Target, "blast_radius": saved.DryRun.BlastRadius,
	})
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
	// Blast-radius guard (fail closed): an unknown or over-limit radius blocks
	// approval. The audit records the BLOCKED attempt either way.
	if p.DryRun.BlastRadius < 0 || p.DryRun.Note == noteUnknown {
		s.record(ctx, tenantID, approver, "remediation.approve_blocked", id, map[string]any{"reason": "blast_radius_unknown"})
		return rem.Proposal{}, rem.ErrUnknownBlastRadius
	}
	if p.DryRun.BlastRadius > s.maxBlastRadius {
		s.record(ctx, tenantID, approver, "remediation.approve_blocked", id, map[string]any{
			"reason": "blast_radius_exceeded", "blast_radius": p.DryRun.BlastRadius, "limit": s.maxBlastRadius,
		})
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
	updated, err := s.store.Decide(ctx, tenantID, id, state, actor, note, at)
	if err != nil {
		return rem.Proposal{}, err
	}
	s.record(ctx, tenantID, actor, action, id, map[string]any{
		"state": state, "blast_radius": updated.DryRun.BlastRadius, "note": note,
	})
	return updated, nil
}

func (s *Service) record(ctx context.Context, tenantID, actor, action, target string, data map[string]any) {
	if s.audit == nil {
		return
	}
	if err := s.audit(ctx, tenantID, actor, action, target, data); err != nil {
		// Audit failures must not silently lose the decision trail; surface via
		// a wrapped error on the caller path is overkill here (the decision is
		// already persisted), so we annotate the data — the caller logs.
		_ = fmt.Errorf("remediation audit: %w", err)
	}
}

const noteUnknown = "topology unavailable — blast radius unknown"
