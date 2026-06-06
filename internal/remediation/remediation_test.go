package remediation

import (
	"errors"
	"testing"
)

func TestValidKind(t *testing.T) {
	for _, k := range []Kind{KindRerouteSuggestion, KindTrafficShiftSuggestion, KindOpenTicket, KindCertRenewal} {
		if !ValidKind(k) {
			t.Errorf("ValidKind(%q) = false, want true", k)
		}
	}
	for _, k := range []Kind{"", "delete_everything", "reboot"} {
		if ValidKind(k) {
			t.Errorf("ValidKind(%q) = true, want false", k)
		}
	}
}

func TestNoExecutedState(t *testing.T) {
	// There must be NO "executed" state anywhere — probectl never executes.
	for _, s := range []State{StateProposed, StateApproved, StateRejected, StateApplied} {
		if s == "executed" {
			t.Fatalf("an 'executed' state exists (%q) — probectl must never execute remediations", s)
		}
	}
}

func TestErrorAsAndCode(t *testing.T) {
	var re Error
	if !errors.As(ErrApprovalsDisabled, &re) || re.Code != "approvals_disabled" {
		t.Fatalf("ErrApprovalsDisabled code = %q", re.Code)
	}
	if ErrBlastRadiusExceeded.Error() == "" || ErrUnknownBlastRadius.Error() == "" || ErrNotProposed.Error() == "" {
		t.Fatal("error messages must be non-empty")
	}
}
