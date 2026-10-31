// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flowconversation

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestActivityRuntimeRequiresActualDrainAndBoundsOwnedRetries(t *testing.T) {
	f := newMessageCodecFixture(t)
	state := &activityRuntime{instance: f.credentialID, pendingLimit: 1, refs: make(map[string]map[string]*activityRef)}
	ref, err := state.reserve(t.Context(), f.scope.TenantID, f.scope.OwnerID)
	if err != nil {
		t.Fatal(err)
	}
	if state.claimRetry(ref) || state.canRetire(ref) {
		t.Fatal("unstarted operation became drain acknowledgement")
	}
	if err := state.setAttempt(ref, 1); err != nil || !state.isActive(ref) {
		t.Fatal("registration attempt did not retain active ownership", err)
	}
	copied := *ref
	if state.isActive(&copied) {
		t.Fatal("copied SQL metadata fabricated a private process reference")
	}
	if !state.drainAndClaim(ref) || !state.canRetire(ref) {
		t.Fatal("actual callback drain did not permit its own retirement")
	}
	if state.isActive(ref) || state.claimRetry(ref) {
		t.Fatal("drained operation still opened source or duplicated retirement")
	}
	state.finishRetirement(ref, ErrJournalUnavailable)
	if _, err := state.reserve(t.Context(), f.scope.TenantID, f.scope.OwnerID); !errors.Is(err, ErrJournalUnavailable) {
		t.Fatal("failed acknowledgements grew same-tenant memory without backpressure", err)
	}
	blue, err := state.reserve(t.Context(), f.scope.ConversationID, f.scope.OwnerID)
	if err != nil {
		t.Fatal("red pending acknowledgement blocked blue admission", err)
	}
	state.abandonUnstarted(blue)
	refs, pending := state.retries(f.scope.TenantID, 1)
	if pending != 1 || len(refs) != 1 || refs[0] != ref || !state.claimRetry(ref) {
		t.Fatal("retry lost exact already-drained ownership")
	}
	if state.canRetire(&copied) {
		t.Fatal("borrowed instance IDs authorized retirement")
	}
	state.finishRetirement(ref, nil)
	if refs, pending := state.retries(f.scope.TenantID, 1); len(refs) != 0 || pending != 0 {
		t.Fatal("confirmed receipt retained sensitive runtime state")
	}
}

func TestActivityCleanupKeepsTenantAndGuardsWithoutCreatorOrLiveLease(t *testing.T) {
	f := newMessageCodecFixture(t)
	ctx := context.WithValue(f.requestContext(t), operationLeaseKey{}, &operationLease{})
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	ref := &activityRef{tenant: f.scope.TenantID}
	cleanup, stop := cleanupActivityContext(canceled, ref)
	defer stop()
	if cleanup.Err() != nil || auth.PrincipalFrom(cleanup) != nil || cleanup.Value(operationLeaseKey{}) != nil {
		t.Fatal("metadata cleanup borrowed canceled creator or source context")
	}
	tenant, ok := tenancy.FromContext(cleanup)
	if !ok || tenant.String() != f.scope.TenantID {
		t.Fatal("independent cleanup lost tenant boundary")
	}
	if deadline, ok := cleanup.Deadline(); !ok || time.Until(deadline) > activityCleanupTimeout {
		t.Fatal("cleanup metadata IO was unbounded")
	}
}

func TestActivityMaintenanceRefusesUnscopedRequestsAndInvalidResources(t *testing.T) {
	f := newMessageCodecFixture(t)
	var journal *Journal
	allow := func(context.Context, string) error { return nil }
	for _, ctx := range []context.Context{t.Context(), f.requestContext(t)} {
		if _, err := journal.RetryDrainedOperations(ctx, ActivityBudget{Rows: 1, TimeLimit: time.Second}, allow); !errors.Is(err, ErrMessageDenied) {
			t.Fatal("request selected independent retry state", err)
		}
	}
	if _, err := journal.RetryDrainedOperations(f.context, ActivityBudget{}, allow); !errors.Is(err, ErrMessageBudget) {
		t.Fatal("nonpositive activity resources reached SQL", err)
	}
	if _, err := journal.RetryDrainedOperations(f.context, ActivityBudget{Rows: 1, TimeLimit: time.Second}, nil); !errors.Is(err, ErrMessageDenied) {
		t.Fatal("missing current runtime authority selected retries", err)
	}
	if _, err := journal.RetryDrainedOperations(f.context, ActivityBudget{Rows: 1, TimeLimit: time.Second}, allow); !errors.Is(err, ErrJournalUnavailable) {
		t.Fatal("healthy runtime retry missed availability check", err)
	}
	if err := journal.WithDrainedInvalidation(f.context, Invalidation{}, allow, func(context.Context) error { t.Error("empty pending reference entered destructive phase"); return nil }); !errors.Is(err, ErrMessageDenied) {
		t.Fatal("empty intent acquired drain authority", err)
	}
}
