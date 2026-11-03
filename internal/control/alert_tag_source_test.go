// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"errors"
	"testing"

	"github.com/ctlplne/probectl/internal/alert"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/store"
)

func TestAlertTagSampleBudgetRejectsForeignUnboundAndCancellation(t *testing.T) {
	for _, labels := range []map[string]string{{}, {"tenant_id": "foreign"}} {
		if err := alertTagSampleBudget(t.Context(), "own", []alert.Sample{{Labels: labels}}, 1<<20); err == nil {
			t.Fatal("foreign or unbound metric source was admitted")
		}
	}
	if err := alertTagSampleBudget(t.Context(), "own", []alert.Sample{{Labels: map[string]string{"tenant_id": "own"}}}, 1); !errors.Is(err, store.ErrTagSnapshotBudget) {
		t.Fatal("source sample budget was ignored")
	}
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	if err := alertTagSampleBudget(canceled, "own", nil, 1<<20); !errors.Is(err, context.Canceled) {
		t.Fatal("empty canceled source was admitted")
	}
}

func TestAlertTagAuthorityIntersectsCredentialScopeAndKeepsMFAEphemeral(t *testing.T) {
	base := &auth.Principal{TenantID: "tenant", UserID: "user", Permissions: map[string]bool{}, Attributes: composeSubjectAttributes(nil, false)}
	for _, key := range append(alertTagPermissions(), permAlertWrite) {
		base.Permissions[key] = true
	}
	a := &alertTagAuthority{current: auth.ClonePrincipal(base), principal: auth.ClonePrincipal(base)}
	actor := auth.ClonePrincipal(base)
	if !a.permitsRequest(actor, permAlertWrite) {
		t.Fatal("current live write was denied without policy")
	}
	delete(actor.Permissions, "metrics.read")
	if a.permitsRequest(actor, "metrics.read") {
		t.Fatal("current user role widened a scoped credential")
	}
	actor = auth.ClonePrincipal(base)
	actor.MFASatisfied = true
	actor.Attributes = composeSubjectAttributes(nil, true)
	a.policies = []auth.Policy{{Name: "live MFA", Effect: auth.PolicyDeny, Permission: "metrics.read", Enabled: true, Subject: map[string]string{"mfa": "false"}}}
	if !a.permitsRequest(actor, "metrics.read") {
		t.Fatal("actual live MFA was not usable for this request")
	}
	if a.permits(a.principal, map[string]string{auth.ResourceTenantKey: "tenant"}) {
		t.Fatal("request MFA became durable background authority")
	}
	if a.current.MFASatisfied || a.principal.MFASatisfied {
		t.Fatal("checking the request mutated the stored/current source principal")
	}
}
