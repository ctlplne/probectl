// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flowconversation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/ctlplne/probectl/internal/tenancy"
)

func maintenanceRequestFixture(f messageCodecFixture) MaintenanceRequest {
	return MaintenanceRequest{ID: f.credentialID, Kind: MaintenanceSubjectErase, Binding: [32]byte{1, 2, 3}}
}
func TestInvalidationRequiresIndependentAuthorityAndExactPlanBeforeSQL(t *testing.T) {
	f := newMessageCodecFixture(t)
	valid := maintenanceRequestFixture(f)
	var journal *Journal
	called := false
	allow := func(context.Context, string) error { called = true; return nil }
	for _, ctx := range []context.Context{t.Context(), f.requestContext(t), tenancy.WithTenant(t.Context(), tenancy.ID("invalid"))} {
		if pending, err := journal.BeginInvalidation(ctx, valid, allow); pending.value != nil || !errors.Is(err, ErrMessageDenied) {
			t.Fatal("request/unscoped identity reached lifecycle storage", err)
		}
	}
	if called {
		t.Fatal("request context invoked independent maintenance authority")
	}
	for _, request := range []MaintenanceRequest{{}, {ID: "bad", Kind: valid.Kind, Binding: valid.Binding}, {ID: valid.ID, Kind: "model_flag", Binding: valid.Binding}, {ID: valid.ID, Kind: valid.Kind}} {
		if pending, err := journal.BeginInvalidation(f.context, request, allow); pending.value != nil || !errors.Is(err, ErrMessageIntegrity) {
			t.Fatal("invalid immutable plan reached lifecycle storage", err)
		}
	}
	if called {
		t.Fatal("invalid plan invoked operational callback")
	}
	if pending, err := journal.BeginInvalidation(f.context, valid, nil); pending.value != nil || !errors.Is(err, ErrMessageDenied) {
		t.Fatal("missing current operational authority reached SQL", err)
	}
	for _, operation := range []func(context.Context, MaintenanceRequest, AuthorizeMaintenance) (Invalidation, error){journal.BeginInvalidation, journal.ResumeInvalidation} {
		if pending, err := operation(f.context, valid, func(context.Context, string) error { return errors.New("revoked") }); pending.value != nil || !errors.Is(err, ErrMessageDenied) {
			t.Fatal("denied operational caller reached SQL", err)
		}
		if pending, err := operation(f.context, valid, allow); pending.value != nil || !errors.Is(err, ErrJournalUnavailable) {
			t.Fatal("valid maintenance did not reach unavailable port", err)
		}
	}
	pending := Invalidation{&invalidation{tenant: f.scope.TenantID, request: valid, generation: 2}}
	if err := journal.WithInvalidationLease(f.context, pending, nil, func(context.Context) error { t.Error("missing authority entered callback"); return nil }); !errors.Is(err, ErrMessageDenied) {
		t.Fatal("missing exact-intent authority reached lease", err)
	}
	foreign := tenancy.WithTenant(f.context, tenancy.ID(f.credentialID))
	if err := journal.WithInvalidationLease(foreign, pending, allow, func(context.Context) error { t.Error("foreign tenant entered callback"); return nil }); !errors.Is(err, ErrMessageDenied) {
		t.Fatal("private intent crossed tenant", err)
	}
	for _, budget := range []CancellationBudget{{}, {Rows: 1}} {
		if batch, err := journal.CancelInvalidated(f.context, pending, budget, allow); batch != (CancellationBatch{}) || !errors.Is(err, ErrMessageBudget) {
			t.Fatal("invalid cancellation resources reached lifecycle storage", err)
		}
	}
	canceled, cancel := context.WithCancel(f.context)
	cancel()
	if pending, err := journal.BeginInvalidation(canceled, valid, allow); pending.value != nil || !errors.Is(err, context.Canceled) {
		t.Fatal("canceled lifecycle selected SQL", err)
	}
}

func TestInvalidationPrivateObjectsNeverBecomeWireAuthority(t *testing.T) {
	f := newMessageCodecFixture(t)
	request := maintenanceRequestFixture(f)
	pending := Invalidation{&invalidation{tenant: f.scope.TenantID, request: request, generation: 2}}
	for _, value := range []any{request, pending} {
		if _, err := json.Marshal(value); !errors.Is(err, errMessagePrivate) {
			t.Fatal("pending lifecycle metadata crossed JSON boundary", err)
		}
		display := fmt.Sprintf("%+v", value)
		if strings.Contains(display, request.ID) || strings.Contains(display, f.scope.TenantID) {
			t.Fatal("private lifecycle formatting disclosed binding")
		}
	}
	if err := json.Unmarshal([]byte(`{}`), new(Invalidation)); !errors.Is(err, errMessagePrivate) {
		t.Fatal("JSON fabricated a pending marker", err)
	}
	if err := json.Unmarshal([]byte(`{}`), new(MaintenanceRequest)); !errors.Is(err, errMessagePrivate) {
		t.Fatal("JSON fabricated a lifecycle plan", err)
	}
}

func TestInvalidationUnavailableStateRemainsRetryable(t *testing.T) {
	f := newMessageCodecFixture(t)
	request := maintenanceRequestFixture(f)
	pending := Invalidation{&invalidation{tenant: f.scope.TenantID, request: request, generation: 2}}
	var journal *Journal
	entered := false
	err := journal.WithInvalidationLease(f.context, pending, func(ctx context.Context, _ string) error { return ctx.Err() }, func(context.Context) error { entered = true; return nil })
	if !errors.Is(err, ErrJournalUnavailable) || entered {
		t.Fatal("unavailable pending-state storage was relabeled as operational denial", err)
	}
}
