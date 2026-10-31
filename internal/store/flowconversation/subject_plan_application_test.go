// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flowconversation

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestSubjectPlanApplicationBoundPrivateBorrowAndRelease(t *testing.T) {
	f := newMessageCodecFixture(t)
	application := []byte(`{"version":1,"stable_id":"` + f.scope.OwnerID + `","alias":"User@Example.Test"}`)
	plan, err := f.codec.PrepareSubjectErasurePlan(f.context, f.credentialID, "User@Example.Test", []string{f.scope.OwnerID}, application)
	if err != nil || plan.value.wire.Version != 2 {
		t.Fatal("application plan refused", err)
	}
	clear(application)
	stored, err := f.codec.sealSubjectPlan(f.context, plan)
	if err != nil || bytes.Contains([]byte(stored), []byte("Example.Test")) {
		t.Fatal("application was not privately encrypted", err)
	}
	opened, err := f.codec.openSubjectPlan(f.context, plan.value.request, stored)
	if err != nil {
		t.Fatal(err)
	}
	var borrowed []byte
	var aliases []string
	if err := opened.VisitSelector(f.context, func(subject string, values []string, app []byte) error {
		if subject != "User@Example.Test" || !slices.Contains(values, f.scope.OwnerID) || !bytes.Contains(app, []byte("Example.Test")) {
			t.Fatal("approved application/selector changed")
		}
		borrowed, aliases = app, values
		clear(app)
		clear(values)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(borrowed, make([]byte, len(borrowed))) || !slices.Equal(aliases, make([]string, len(aliases))) {
		t.Fatal("borrowed copies survived the visitor")
	}
	if err := opened.VisitSelector(f.context, func(_ string, values []string, app []byte) error {
		if !slices.Contains(values, f.scope.OwnerID) || !bytes.Contains(app, []byte("Example.Test")) {
			t.Error("visitor mutated the immutable approved plan")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for _, ctx := range []context.Context{t.Context(), f.requestContext(t), tenancy.WithTenant(f.context, tenancy.ID(f.scope.MessageID))} {
		if err := opened.VisitSelector(ctx, func(string, []string, []byte) error { t.Error("foreign/request selector entered"); return nil }); !errors.Is(err, ErrMessageDenied) {
			t.Fatal("private selector changed tenant/request domain", err)
		}
	}
	changed := plan.value.request
	changed.Binding[0] ^= 1
	if _, err := f.codec.openSubjectPlan(f.context, changed, stored); !errors.Is(err, ErrMessageIntegrity) {
		t.Fatal("application replayed under another binding", err)
	}
	opened.Release()
	if err := opened.VisitSelector(f.context, func(string, []string, []byte) error { t.Error("released selector revived"); return nil }); !errors.Is(err, ErrMessageDenied) {
		t.Fatal("released selector remained readable", err)
	}
}

func TestSubjectPlanApplicationRequiresCompleteDataAndAtomicValidator(t *testing.T) {
	f := newMessageCodecFixture(t)
	for _, app := range [][]byte{nil, []byte(`[]`), []byte(`false`), []byte(`{} {}`), {0xff}} {
		if _, err := f.codec.PrepareSubjectErasurePlan(f.context, f.credentialID, "a@example.test", nil, app); !errors.Is(err, ErrMessageIntegrity) {
			t.Fatal("invalid application entered plan", err)
		}
	}
	plan, err := f.codec.PrepareSubjectErasurePlan(f.context, f.credentialID, "a@example.test", nil, []byte(`{"version":1}`))
	if err != nil {
		t.Fatal(err)
	}
	defer plan.Release()
	var journal *Journal
	allow := func(context.Context, string) error { return nil }
	if _, err := journal.BeginSubjectInvalidation(f.context, f.codec, plan, allow); !errors.Is(err, ErrMessageDenied) {
		t.Fatal("application plan reached SQL without atomic validation", err)
	}
	if _, err := journal.BeginSubjectInvalidation(f.context, f.codec, plan, allow, nil); !errors.Is(err, ErrMessageDenied) {
		t.Fatal("nil atomic validator reached SQL", err)
	}
	called := false
	if _, err := journal.BeginSubjectInvalidation(f.context, f.codec, plan, allow, func(context.Context, tenancy.Scope) error { called = true; return nil }); !errors.Is(err, ErrJournalUnavailable) || called {
		t.Fatal("atomic validator ran outside a real transaction", err)
	}
}
