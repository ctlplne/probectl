// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package auth

import "testing"

func pol(name string, effect PolicyEffect, perm string, subj map[string]string, pri int) Policy {
	return Policy{Name: name, Effect: effect, Permission: perm, Subject: subj, Priority: pri, Enabled: true}
}

func TestEvaluateDenyOverride(t *testing.T) {
	policies := []Policy{pol("no-contractor-write", PolicyDeny, "test.write", map[string]string{"department": "contractor"}, 10)}
	if got := Evaluate(policies, "test.write", map[string]string{"department": "contractor"}, nil); got != PolicyDeny {
		t.Errorf("contractor write = %q, want deny", got)
	}
	if got := Evaluate(policies, "test.write", map[string]string{"department": "netops"}, nil); got != "" {
		t.Errorf("non-matching subject = %q, want silent", got)
	}
	if got := Evaluate(policies, "test.read", map[string]string{"department": "contractor"}, nil); got != "" {
		t.Errorf("non-matching permission = %q, want silent", got)
	}
}

func TestEvaluatePriorityAndTies(t *testing.T) {
	policies := []Policy{
		pol("allow-hi", PolicyAllow, "*", map[string]string{"role": "admin"}, 20),
		pol("deny-lo", PolicyDeny, "*", map[string]string{"role": "admin"}, 10),
	}
	if got := Evaluate(policies, "x", map[string]string{"role": "admin"}, nil); got != PolicyAllow {
		t.Errorf("higher-priority allow = %q, want allow", got)
	}
	tie := []Policy{
		pol("a", PolicyAllow, "*", map[string]string{"role": "admin"}, 10),
		pol("d", PolicyDeny, "*", map[string]string{"role": "admin"}, 10),
	}
	if got := Evaluate(tie, "x", map[string]string{"role": "admin"}, nil); got != PolicyDeny {
		t.Errorf("tie = %q, want deny-override", got)
	}
}

func TestEvaluateResourceMFAAndDisabled(t *testing.T) {
	// step-up: deny incident.write when not MFA-satisfied
	mfa := []Policy{pol("step-up", PolicyDeny, "incident.write", map[string]string{"mfa": "false"}, 5)}
	if got := Evaluate(mfa, "incident.write", map[string]string{"mfa": "false"}, nil); got != PolicyDeny {
		t.Errorf("no-mfa = %q, want deny", got)
	}
	if got := Evaluate(mfa, "incident.write", map[string]string{"mfa": "true"}, nil); got != "" {
		t.Errorf("mfa-satisfied = %q, want silent", got)
	}

	// delegated admin: deny outside the subject's org (resource-attribute match)
	res := []Policy{{Name: "org-scope", Effect: PolicyDeny, Permission: "test.write", Resource: map[string]string{"org": "other"}, Priority: 5, Enabled: true}}
	if got := Evaluate(res, "test.write", nil, map[string]string{"org": "other"}); got != PolicyDeny {
		t.Errorf("resource match = %q, want deny", got)
	}
	if got := Evaluate(res, "test.write", nil, map[string]string{"org": "mine"}); got != "" {
		t.Errorf("resource non-match = %q, want silent", got)
	}

	// a disabled policy is ignored
	dis := []Policy{{Name: "off", Effect: PolicyDeny, Permission: "*", Subject: map[string]string{"x": "y"}, Enabled: false}}
	if got := Evaluate(dis, "z", map[string]string{"x": "y"}, nil); got != "" {
		t.Errorf("disabled = %q, want silent", got)
	}
}

func TestPermit(t *testing.T) {
	p := &Principal{Permissions: map[string]bool{"test.write": true}, Attributes: map[string]string{"department": "contractor"}}
	deny := []Policy{pol("no-contractor", PolicyDeny, "test.write", map[string]string{"department": "contractor"}, 1)}
	if permit(p, "test.write", deny, nil) {
		t.Error("ABAC deny should block an RBAC-permitted action")
	}
	if !permit(p, "test.write", nil, nil) {
		t.Error("RBAC-permitted with no policy should permit")
	}
	if permit(p, "agent.write", nil, nil) {
		t.Error("missing RBAC permission must not permit (RBAC is the baseline)")
	}
}
