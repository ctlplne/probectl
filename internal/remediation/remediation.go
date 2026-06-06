// Package remediation is the CORE model + seam for guarded agentic remediation
// (S-EE5, F44 — guardrail-critical). The AI PROPOSES network remediations
// grounded in RCA (S24) + topology what-if (S43); a human APPROVES; probectl
// itself NEVER acts. This package defines the proposal model and the Service
// seam; ee/remediation implements the workflow (the `remediation` Enterprise
// feature), installed at the attach seam.
//
// The ratified policy (human sign-off, CLAUDE.md §2/§7 guardrail 8):
//
//   - PROPOSAL-ONLY: there is NO executor anywhere in the code. "Approve" is a
//     recorded, audited human sign-off; operators carry the action out
//     out-of-band. probectl never reroutes traffic / mutates the network.
//   - INGESTED DATA CAN NEVER TRIGGER OR APPROVE AN ACTION. The MCP
//     propose_remediation tool can only ever create a PROPOSED proposal that a
//     human must approve through the authenticated UI; a prompt-injection in
//     telemetry can at most file a proposal, never approve one.
//   - ADVISORY-ONLY BY DEFAULT: approvals are OFF until an operator enables
//     them (PROBECTL_REMEDIATION_APPROVALS_ENABLED=false by default).
//   - SINGLE-ADMIN APPROVE: an authenticated principal holding remediation.approve.
//   - BLAST-RADIUS LIMITED: a proposal whose simulated blast radius exceeds the
//     configured maximum cannot be approved.
//   - FULLY AUDITED: propose / approve / reject are written to the tamper-evident
//     tenant audit stream.
package remediation

import (
	"context"
	"time"
)

// Kind is the type of remediation an AI may propose. Every kind is a
// SUGGESTION — probectl never executes any of them.
type Kind string

const (
	KindRerouteSuggestion      Kind = "reroute_suggestion"       // suggest rerouting around a failing element
	KindTrafficShiftSuggestion Kind = "traffic_shift_suggestion" // suggest shifting traffic/weights
	KindOpenTicket             Kind = "open_ticket"              // suggest opening an ITSM ticket
	KindCertRenewal            Kind = "trustctl_renewal"         // suggest a trustctl certificate renewal
)

// ValidKind reports whether k is a known remediation kind.
func ValidKind(k Kind) bool {
	switch k {
	case KindRerouteSuggestion, KindTrafficShiftSuggestion, KindOpenTicket, KindCertRenewal:
		return true
	}
	return false
}

// State is a proposal's lifecycle. There is deliberately NO "executed" state —
// probectl never executes. "applied" is an OPERATOR-recorded note that a human
// carried the suggestion out elsewhere; it changes nothing in probectl.
type State string

const (
	StateProposed State = "proposed" // awaiting a human decision
	StateApproved State = "approved" // a human authorized it (recorded; not executed by probectl)
	StateRejected State = "rejected" // a human declined it
	StateApplied  State = "applied"  // an operator recorded that they carried it out (no probectl action)
)

// DryRun is the simulated impact of a proposal — the S43 what-if preview. It
// EXECUTES NOTHING; it is a read-only graph simulation used to size the blast
// radius and show operators what the suggestion would affect.
type DryRun struct {
	BlastRadius      int      `json:"blast_radius"` // count of affected entities
	ImpactedServices []string `json:"impacted_services,omitempty"`
	ImpactedPrefixes []string `json:"impacted_prefixes,omitempty"`
	Disconnected     []string `json:"disconnected,omitempty"`
	Note             string   `json:"note,omitempty"` // e.g. "topology unavailable — blast radius unknown"
}

// Proposal is one AI-proposed remediation and its decision trail.
type Proposal struct {
	ID         string     `json:"id"`
	TenantID   string     `json:"tenant_id"`
	Kind       Kind       `json:"kind"`
	Title      string     `json:"title"`
	Rationale  string     `json:"rationale"`             // grounded in RCA / the incident
	Target     string     `json:"target"`                // the affected element (e.g. "hop:10.0.0.1")
	IncidentID string     `json:"incident_id,omitempty"` // the grounding incident, when any
	DryRun     DryRun     `json:"dry_run"`
	State      State      `json:"state"`
	ProposedBy string     `json:"proposed_by"`          // a user, or "ai:propose_remediation"
	DecidedBy  string     `json:"decided_by,omitempty"` // the approver/rejecter
	Decision   string     `json:"decision_note,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	DecidedAt  *time.Time `json:"decided_at,omitempty"`
}

// ProposeInput is the AI/operator's proposal request. The proposer is taken
// from the authenticated principal, never from the input.
type ProposeInput struct {
	Kind       Kind
	Title      string
	Rationale  string
	Target     string
	IncidentID string
}

// Service is the remediation workflow seam. ee/remediation implements it; the
// control plane calls it. nil = the feature is not licensed (the surface 404s).
type Service interface {
	// Propose files a PROPOSED proposal (running the dry-run) — never approves.
	// proposedBy is the authenticated caller (or "ai:..." for the MCP tool).
	Propose(ctx context.Context, tenantID, proposedBy string, in ProposeInput) (Proposal, error)
	// List returns the tenant's proposals (newest first).
	List(ctx context.Context, tenantID string) ([]Proposal, error)
	// Get returns one proposal.
	Get(ctx context.Context, tenantID, id string) (Proposal, error)
	// Approve records a human's authorization — fails closed if approvals are
	// disabled (advisory-only) or the blast radius exceeds the limit. probectl
	// executes NOTHING; this only records + audits the decision.
	Approve(ctx context.Context, tenantID, approver, id, note string) (Proposal, error)
	// Reject records a human's decline.
	Reject(ctx context.Context, tenantID, decider, id, note string) (Proposal, error)
	// ApprovalsEnabled reports the advisory-only master switch (surfaced so the
	// UI can disable/relabel the Approve action).
	ApprovalsEnabled() bool
}

// Estimator computes a proposal's blast radius via the S43 topology what-if.
// It is read-only and EXECUTES NOTHING. A nil/zero result with an error note is
// treated conservatively (unknown blast radius blocks approval).
type Estimator interface {
	Estimate(ctx context.Context, tenantID, target string) DryRun
}

// ErrApprovalsDisabled / ErrBlastRadiusExceeded / ErrNotProposed are the
// fail-closed approval errors (the transport maps them to 4xx).
type Error struct{ Code, Message string }

func (e Error) Error() string { return e.Message }

var (
	ErrApprovalsDisabled   = Error{Code: "approvals_disabled", Message: "remediation approvals are disabled (advisory-only) — an operator must enable them"}
	ErrBlastRadiusExceeded = Error{Code: "blast_radius_exceeded", Message: "the proposal's blast radius exceeds the configured limit — it cannot be approved"}
	ErrNotProposed         = Error{Code: "not_proposed", Message: "only a proposed remediation can be decided"}
	ErrUnknownBlastRadius  = Error{Code: "blast_radius_unknown", Message: "the blast radius could not be simulated (topology unavailable) — approval is blocked, fail closed"}
)
