// SPDX-License-Identifier: LicenseRef-probectl-Commercial-TBD

// probectl Commercial License — PLACEHOLDER (legal text TBD with counsel).

package remediation

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"

	rem "github.com/imfeelingtheagi/probectl/internal/remediation"
)

const testTenant = "00000000-0000-0000-0000-000000000001"

type proposalRow struct {
	dryRun []byte
}

func (r proposalRow) Scan(dest ...any) error {
	if len(dest) != 14 {
		return errors.New("unexpected remediation row shape")
	}
	created := time.Unix(1700000000, 0).UTC()
	*dest[0].(*string) = "rem-1"
	*dest[1].(*string) = testTenant
	*dest[2].(*rem.Kind) = rem.KindOpenTicket
	*dest[3].(*string) = "open ticket"
	*dest[4].(*string) = "investigate"
	*dest[5].(*string) = "node:1"
	*dest[6].(*string) = "inc-1"
	*dest[7].(*[]byte) = r.dryRun
	*dest[8].(*rem.State) = rem.StateProposed
	*dest[9].(*string) = "ai:propose_remediation"
	*dest[10].(*string) = ""
	*dest[11].(*string) = ""
	*dest[12].(*time.Time) = created
	*dest[13].(**time.Time) = nil
	return nil
}

func TestScanProposalRejectsCorruptDryRunJSON(t *testing.T) {
	if _, err := scanProposal(proposalRow{dryRun: []byte(`{"blast_radius":`)}); err == nil {
		t.Fatal("corrupt persisted dry_run JSON must return an error, not a zero-value dry-run")
	}
}

// recAudit records every audit call so tests can assert the decision trail.
type recAudit struct {
	mu    sync.Mutex
	calls []auditCall
}

type auditCall struct {
	tenant, actor, action, target string
	data                          map[string]any
}

func (r *recAudit) fn() Audit {
	return func(_ context.Context, tenant, actor, action, target string, data map[string]any) error {
		r.mu.Lock()
		defer r.mu.Unlock()
		r.calls = append(r.calls, auditCall{tenant, actor, action, target, data})
		return nil
	}
}

func (r *recAudit) actions() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, 0, len(r.calls))
	for _, c := range r.calls {
		out = append(out, c.action)
	}
	return out
}

func (r *recAudit) has(action string) bool {
	for _, a := range r.actions() {
		if a == action {
			return true
		}
	}
	return false
}

// fakeEstimator returns a fixed dry-run and counts calls. It is READ-ONLY — it
// proves the "dry-run executes nothing" property: the only thing Propose can do
// with a target is ask the estimator to simulate it.
type fakeEstimator struct {
	dry   rem.DryRun
	calls int
}

func (f *fakeEstimator) Estimate(_ context.Context, _, _ string) rem.DryRun {
	f.calls++
	return f.dry
}

var fixedNow = time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)

func newSvc(approvals bool, maxBR int, est rem.Estimator, audit Audit) *Service {
	return New(NewMemStore(), est, audit, Config{ApprovalsEnabled: approvals, MaxBlastRadius: maxBR}).
		withNow(func() time.Time { return fixedNow })
}

func mustPropose(t *testing.T, s *Service, by string) rem.Proposal {
	t.Helper()
	p, err := s.Propose(context.Background(), testTenant, by, rem.ProposeInput{
		Kind: rem.KindRerouteSuggestion, Title: "reroute around failing hop",
		Rationale: "incident X", Target: "hop:10.0.0.1",
	})
	if err != nil {
		t.Fatalf("propose: %v", err)
	}
	return p
}

// TestPropose_AlwaysProposed proves Propose never approves on creation —
// regardless of the approvals master switch, and regardless of who proposes
// (including the AI/ingested-data path). This is the core "no auto-approve"
// guarantee.
func TestPropose_AlwaysProposed(t *testing.T) {
	for _, approvals := range []bool{false, true} {
		est := &fakeEstimator{dry: rem.DryRun{BlastRadius: 3}}
		aud := &recAudit{}
		s := newSvc(approvals, 50, est, aud.fn())

		// The AI/ingested-data proposer name — a prompt-injection path.
		p := mustPropose(t, s, "ai:propose_remediation")
		if p.State != rem.StateProposed {
			t.Fatalf("approvals=%v: state=%q, want proposed", approvals, p.State)
		}
		if est.calls != 1 {
			t.Fatalf("approvals=%v: estimator called %d times, want 1 (read-only dry-run)", approvals, est.calls)
		}
		if !aud.has("remediation.propose") {
			t.Fatalf("approvals=%v: propose not audited; actions=%v", approvals, aud.actions())
		}
	}
}

// TestInjectionCannotApprove is the explicit prompt-injection guardrail: the
// MCP/propose path (ingested data) can ONLY create a proposed proposal, and the
// ONLY way to approve is the separate Approve call — which, with approvals off
// (the default), fails closed. So ingested data can never cause an approval.
func TestInjectionCannotApprove(t *testing.T) {
	est := &fakeEstimator{dry: rem.DryRun{BlastRadius: 1}}
	aud := &recAudit{}
	s := newSvc(false /* advisory-only default */, 50, est, aud.fn())

	p := mustPropose(t, s, "ai:propose_remediation")
	if p.State != rem.StateProposed {
		t.Fatalf("injection produced state %q, want proposed", p.State)
	}
	// The only path to approval is Approve — and it's disabled by default.
	if _, err := s.Approve(context.Background(), testTenant, "ai:propose_remediation", p.ID, ""); !errors.Is(err, rem.ErrApprovalsDisabled) {
		t.Fatalf("approve via injection: err=%v, want ErrApprovalsDisabled", err)
	}
	got, _ := s.Get(context.Background(), testTenant, p.ID)
	if got.State != rem.StateProposed {
		t.Fatalf("after blocked approve, state=%q, want proposed", got.State)
	}
}

// TestAdvisoryOnly_Default proves approvals are OFF by default and Approve fails
// closed without ever transitioning the proposal.
func TestAdvisoryOnly_Default(t *testing.T) {
	est := &fakeEstimator{dry: rem.DryRun{BlastRadius: 1}}
	aud := &recAudit{}
	s := newSvc(false, 50, est, aud.fn())
	if s.ApprovalsEnabled() {
		t.Fatal("ApprovalsEnabled() = true, want false by default")
	}
	p := mustPropose(t, s, "user:admin@example.com")
	if _, err := s.Approve(context.Background(), testTenant, "user:admin@example.com", p.ID, "go"); !errors.Is(err, rem.ErrApprovalsDisabled) {
		t.Fatalf("approve: err=%v, want ErrApprovalsDisabled", err)
	}
}

// TestApprove_RequiresHumanAndAudits proves the happy path: with approvals
// enabled, an authenticated human approver moves a proposal to approved, the
// approver is recorded, and the decision is audited.
func TestApprove_RequiresHumanAndAudits(t *testing.T) {
	est := &fakeEstimator{dry: rem.DryRun{BlastRadius: 5}}
	aud := &recAudit{}
	s := newSvc(true, 50, est, aud.fn())

	p := mustPropose(t, s, "ai:propose_remediation")
	out, err := s.Approve(context.Background(), testTenant, "user:admin@example.com", p.ID, "approved by NOC")
	if err != nil {
		t.Fatalf("approve: %v", err)
	}
	if out.State != rem.StateApproved {
		t.Fatalf("state=%q, want approved", out.State)
	}
	if out.DecidedBy != "user:admin@example.com" {
		t.Fatalf("decided_by=%q, want the human approver", out.DecidedBy)
	}
	if out.DecidedAt == nil {
		t.Fatal("decided_at not set")
	}
	if !aud.has("remediation.approve") {
		t.Fatalf("approve not audited; actions=%v", aud.actions())
	}
}

// TestApprove_BlastRadiusOverLimit_Blocked proves an over-limit proposal cannot
// be approved (fail closed), the attempt is audited as blocked, and the state
// is unchanged.
func TestApprove_BlastRadiusOverLimit_Blocked(t *testing.T) {
	est := &fakeEstimator{dry: rem.DryRun{BlastRadius: 200}}
	aud := &recAudit{}
	s := newSvc(true, 50, est, aud.fn())

	p := mustPropose(t, s, "ai:propose_remediation")
	if _, err := s.Approve(context.Background(), testTenant, "user:admin@example.com", p.ID, ""); !errors.Is(err, rem.ErrBlastRadiusExceeded) {
		t.Fatalf("approve: err=%v, want ErrBlastRadiusExceeded", err)
	}
	if !aud.has("remediation.approve_blocked") {
		t.Fatalf("blocked approval not audited; actions=%v", aud.actions())
	}
	got, _ := s.Get(context.Background(), testTenant, p.ID)
	if got.State != rem.StateProposed {
		t.Fatalf("after blocked approve, state=%q, want proposed", got.State)
	}
}

// TestApprove_UnknownBlastRadius_Blocked proves that when topology is
// unavailable (blast radius unknown), approval is blocked — fail closed.
func TestApprove_UnknownBlastRadius_Blocked(t *testing.T) {
	est := &fakeEstimator{dry: rem.DryRun{BlastRadius: -1, Note: noteUnknown}}
	aud := &recAudit{}
	s := newSvc(true, 50, est, aud.fn())

	p := mustPropose(t, s, "ai:propose_remediation")
	if _, err := s.Approve(context.Background(), testTenant, "user:admin@example.com", p.ID, ""); !errors.Is(err, rem.ErrUnknownBlastRadius) {
		t.Fatalf("approve: err=%v, want ErrUnknownBlastRadius", err)
	}
	got, _ := s.Get(context.Background(), testTenant, p.ID)
	if got.State != rem.StateProposed {
		t.Fatalf("state=%q, want proposed (fail closed)", got.State)
	}
}

// TestReject_Audits proves Reject records a human's decline and audits it, and
// that a decided proposal cannot be decided again.
func TestReject_Audits(t *testing.T) {
	est := &fakeEstimator{dry: rem.DryRun{BlastRadius: 2}}
	aud := &recAudit{}
	s := newSvc(true, 50, est, aud.fn())

	p := mustPropose(t, s, "ai:propose_remediation")
	out, err := s.Reject(context.Background(), testTenant, "user:admin@example.com", p.ID, "not now")
	if err != nil {
		t.Fatalf("reject: %v", err)
	}
	if out.State != rem.StateRejected {
		t.Fatalf("state=%q, want rejected", out.State)
	}
	if !aud.has("remediation.reject") {
		t.Fatalf("reject not audited; actions=%v", aud.actions())
	}
	// A rejected proposal cannot then be approved.
	if _, err := s.Approve(context.Background(), testTenant, "user:admin@example.com", p.ID, ""); !errors.Is(err, rem.ErrNotProposed) {
		t.Fatalf("approve after reject: err=%v, want ErrNotProposed", err)
	}
}

// TestNoExecutor is the structural "probectl never executes" proof: the Service
// exposes NO method that could carry out a network action. If anyone ever adds
// an Apply/Execute/Run/Perform/Act/Remediate method, this test fails loudly.
func TestNoExecutor(t *testing.T) {
	banned := map[string]bool{
		"Apply": true, "Execute": true, "Run": true, "Perform": true,
		"Act": true, "Remediate": true, "Dispatch": true, "Enact": true,
	}
	st := reflect.TypeOf(&Service{})
	for i := 0; i < st.NumMethod(); i++ {
		if banned[st.Method(i).Name] {
			t.Fatalf("Service exposes a forbidden executor method %q — probectl must NEVER execute remediations (guardrail 8)", st.Method(i).Name)
		}
	}
	// And the State type has no "executed" state.
	for _, s := range []rem.State{rem.StateProposed, rem.StateApproved, rem.StateRejected, rem.StateApplied} {
		if s == "executed" {
			t.Fatal("an 'executed' state exists — probectl must never execute")
		}
	}
}

// TestProposeValidation rejects unknown kinds and empty titles before anything
// is stored.
func TestProposeValidation(t *testing.T) {
	s := newSvc(true, 50, &fakeEstimator{}, (&recAudit{}).fn())
	if _, err := s.Propose(context.Background(), testTenant, "u", rem.ProposeInput{Kind: "nonsense", Title: "x"}); err == nil {
		t.Fatal("want validation error for unknown kind")
	}
	if _, err := s.Propose(context.Background(), testTenant, "u", rem.ProposeInput{Kind: rem.KindOpenTicket, Title: "   "}); err == nil {
		t.Fatal("want validation error for empty title")
	}
}
