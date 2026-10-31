// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flowconversation

import (
	"context"
	"errors"
	"math"
	"testing"

	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestDispatchTerminalBoundaryBeforeSQL(t *testing.T) {
	f := newMessageCodecFixture(t)
	valid := dispatchCandidate{scope: f.scope, job: f.credentialID, status: "queued"}
	var journal *Journal
	if err := journal.FailDispatch(f.context, DispatchCandidate{}, DispatchOriginInvalid, f.authorizeDispatch); !errors.Is(err, ErrMessageIntegrity) {
		t.Fatal("empty candidate acquired cleanup authority", err)
	}
	if err := journal.FailDispatch(f.context, DispatchCandidate{&valid}, DispatchFailure(255), f.authorizeDispatch); !errors.Is(err, ErrMessageIntegrity) {
		t.Fatal("arbitrary terminal reason reached SQL", err)
	}
	for _, change := range []func(*dispatchCandidate){
		func(c *dispatchCandidate) { c.job = "bad" },
		func(c *dispatchCandidate) { c.status = "completed" },
		func(c *dispatchCandidate) { c.generation = math.MaxInt64 },
		func(c *dispatchCandidate) { c.cancellation = math.MaxUint64 },
		func(c *dispatchCandidate) { c.scope.Revision = math.MaxUint64 },
	} {
		value := valid
		change(&value)
		if err := journal.FailDispatch(f.context, DispatchCandidate{&value}, DispatchSourceInvalid, f.authorizeDispatch); !errors.Is(err, ErrMessageIntegrity) {
			t.Fatal("invalid/stale/overflow metadata reached SQL", err)
		}
	}
	for _, ctx := range []context.Context{f.requestContext(t), tenancy.WithTenant(f.context, tenancy.ID(f.credentialID))} {
		if err := journal.FailDispatch(ctx, DispatchCandidate{&valid}, DispatchOriginInvalid, f.authorizeDispatch); err == nil || errors.Is(err, ErrJournalUnavailable) {
			t.Fatal("request/foreign tenant selected internal terminal SQL", err)
		}
	}
	if err := journal.FailDispatch(f.context, DispatchCandidate{&valid}, DispatchOriginInvalid, nil); !errors.Is(err, ErrMessageDenied) {
		t.Fatal("missing independent cleanup authority reached SQL", err)
	}
	if err := journal.FailDispatch(f.context, DispatchCandidate{&valid}, DispatchOriginInvalid, f.authorizeDispatch); !errors.Is(err, ErrJournalUnavailable) {
		t.Fatal("healthy source-free cleanup did not reach availability check", err)
	}
	ctx, cancel := context.WithCancel(f.context)
	cancel()
	if err := journal.FailDispatch(ctx, DispatchCandidate{&valid}, DispatchOriginInvalid, f.authorizeDispatch); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled cleanup reached SQL", err)
	}
}
