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
	"time"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func (f messageCodecFixture) authorizeDispatch(_ context.Context, tenant, owner string) error {
	if tenant != f.scope.TenantID || owner != f.scope.OwnerID {
		return ErrMessageDenied
	}
	return nil
}

func TestDispatchBoundaryRefusesRequestAuthorityBeforeCallbackOrSQL(t *testing.T) {
	f := newMessageCodecFixture(t)
	budget := DispatchBudget{Rows: 1, HeaderBytes: 1 << 20, TimeLimit: time.Second}
	var journal *Journal
	calls := 0
	allow := func(context.Context, string, string) error { calls++; return nil }
	for _, ctx := range []context.Context{
		t.Context(),
		f.requestContext(t),
		auth.WithPrincipal(f.context, &auth.Principal{TenantID: f.scope.TenantID, UserID: f.scope.OwnerID}),
		tenancy.WithTenant(f.context, tenancy.ID("not-a-tenant")),
	} {
		page, err := journal.DispatchPage(ctx, f.scope.OwnerID, nil, budget, allow)
		if page.Candidates != nil || !errors.Is(err, ErrMessageDenied) || calls != 0 {
			t.Fatal("request/missing/invalid tenant selected independent internal authority", err, calls)
		}
	}
	if _, err := journal.DispatchPage(f.context, "invalid-owner", nil, budget, allow); !errors.Is(err, ErrMessageDenied) || calls != 0 {
		t.Fatal("invalid owner selected authority", err)
	}
	if _, err := journal.DispatchPage(f.context, f.scope.OwnerID, nil, DispatchBudget{}, allow); !errors.Is(err, ErrMessageBudget) || calls != 0 {
		t.Fatal("nonpositive resource selected authority", err)
	}
	if _, err := journal.DispatchPage(f.context, f.scope.OwnerID, nil, budget, nil); !errors.Is(err, ErrMessageDenied) {
		t.Fatal("missing internal authority reached SQL", err)
	}
	for _, cursor := range []*DispatchCursor{
		{},
		{&dispatchCursor{tenant: f.scope.TenantID, owner: f.credentialID, after: f.credentialID, epoch: 1}},
		{&dispatchCursor{tenant: f.scope.TenantID, owner: f.scope.OwnerID, after: "bad", epoch: 1}},
		{&dispatchCursor{tenant: f.scope.TenantID, owner: f.scope.OwnerID, after: f.credentialID}},
	} {
		if _, err := journal.DispatchPage(f.context, f.scope.OwnerID, cursor, budget, allow); err == nil || errors.Is(err, ErrJournalUnavailable) || calls != 0 {
			t.Fatal("invalid continuation reached authority or SQL", err)
		}
	}
	deny := func(context.Context, string, string) error { return errors.New("private operational failure") }
	if _, err := journal.DispatchPage(f.context, f.scope.OwnerID, nil, budget, deny); !errors.Is(err, ErrMessageDenied) || strings.Contains(err.Error(), "private operational failure") {
		t.Fatal("internal refusal leaked diagnostics or reached SQL", err)
	}
	if _, err := journal.DispatchPage(f.context, f.scope.OwnerID, nil, budget, allow); !errors.Is(err, ErrJournalUnavailable) || calls != 1 {
		t.Fatal("authorized source-free metadata did not reach unavailable SQL", err)
	}
	canceled, cancel := context.WithCancel(f.context)
	cancel()
	if _, err := journal.DispatchPage(canceled, f.scope.OwnerID, nil, budget, allow); !errors.Is(err, context.Canceled) || calls != 1 {
		t.Fatal("canceled metadata reached internal authority", err)
	}
	timed := func(ctx context.Context, _, _ string) error {
		<-ctx.Done()
		return ctx.Err()
	}
	budget.TimeLimit = time.Millisecond
	if _, err := journal.DispatchPage(f.context, f.scope.OwnerID, nil, budget, timed); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("internal authorization ignored page deadline", err)
	}
}

func TestDispatchPrivateValuesDoNotSerializeOrRevealHeaders(t *testing.T) {
	marker := "owned-private-header-marker"
	for _, value := range []any{
		DispatchCandidate{&dispatchCandidate{header: marker}},
		DispatchCursor{&dispatchCursor{owner: marker}},
		DispatchPage{},
	} {
		if _, err := json.Marshal(value); !errors.Is(err, errMessagePrivate) {
			t.Fatal("private dispatch value crossed JSON", err)
		}
		if strings.Contains(fmt.Sprintf("%+v", value), marker) || strings.Contains(fmt.Sprintf("%#v", value), marker) {
			t.Fatal("private dispatch backing appeared in diagnostics")
		}
	}
	for _, value := range []any{new(DispatchCandidate), new(DispatchCursor)} {
		if err := json.Unmarshal([]byte(`{}`), value); !errors.Is(err, errMessagePrivate) {
			t.Fatal("wire data constructed a private continuation", err)
		}
	}
	if (DispatchCandidate{}).Scope() != (MessageScope{}) {
		t.Fatal("empty candidate acquired scope")
	}
}

func TestDispatchHeaderBootstrapAuthenticatesOriginWithoutPayload(t *testing.T) {
	f := newMessageCodecFixture(t)
	sealed := f.seal(t, []byte(`{"question":"source must stay closed"}`))
	candidate := DispatchCandidate{&dispatchCandidate{scope: f.scope, header: sealed.parts.header}}
	open := f.codec.open
	opens, callbacks := 0, 0
	f.codec.open = func(ctx context.Context, tenant, value string, aad []byte) ([]byte, error) {
		opens++
		if value != sealed.parts.header || string(aad) != string(f.scope.aad('h')) {
			t.Fatal("source payload or foreign header opened during bootstrap")
		}
		return open(ctx, tenant, value, aad)
	}
	allow := func(ctx context.Context, scope MessageScope, origin auth.WorkerCredentialRef, required []string) error {
		callbacks++
		return f.authorize(ctx, scope, origin, required)
	}
	if err := f.codec.BootstrapDispatch(f.context, candidate, f.authorizeDispatch, allow); err != nil || opens != 1 || callbacks != 1 {
		t.Fatal("authenticated original provenance unavailable without payload", err)
	}
	for _, ctx := range []context.Context{
		f.requestContext(t),
		tenancy.WithTenant(f.context, tenancy.ID(f.credentialID)),
	} {
		if err := f.codec.BootstrapDispatch(ctx, candidate, f.authorizeDispatch, allow); err == nil || opens != 1 || callbacks != 1 {
			t.Fatal("request/foreign tenant reached header crypto", err)
		}
	}
	deny := func(context.Context, MessageScope, auth.WorkerCredentialRef, []string) error {
		return errors.New("private current authority diagnostic")
	}
	if err := f.codec.BootstrapDispatch(f.context, candidate, f.authorizeDispatch, deny); !errors.Is(err, ErrMessageDenied) || strings.Contains(err.Error(), "private current authority diagnostic") {
		t.Fatal("current authority refusal failed closed", err)
	}
	if err := f.codec.BootstrapDispatch(f.context, candidate, f.authorizeDispatch, nil); !errors.Is(err, ErrMessageIntegrity) {
		t.Fatal("missing callback admitted stored origin", err)
	}
}

func TestDispatchHeaderBootstrapScopeIntegrityAndBudgets(t *testing.T) {
	f := newMessageCodecFixture(t)
	sealed := f.seal(t, []byte(`{"q":"owned source"}`))
	valid := dispatchCandidate{scope: f.scope, header: sealed.parts.header}
	for _, change := range []func(*dispatchCandidate){
		func(c *dispatchCandidate) { c.scope.OwnerID = f.credentialID },
		func(c *dispatchCandidate) { c.scope.ConversationID = f.credentialID },
		func(c *dispatchCandidate) { c.scope.MessageID = f.credentialID },
		func(c *dispatchCandidate) { c.scope.Revision++ },
		func(c *dispatchCandidate) { c.scope.Epoch++ },
		func(c *dispatchCandidate) { c.header = "plaintext-refused" },
		func(c *dispatchCandidate) { c.header += "tamper" },
	} {
		value := valid
		change(&value)
		calls := 0
		err := f.codec.BootstrapDispatch(f.context, DispatchCandidate{&value}, f.authorizeDispatch, func(context.Context, MessageScope, auth.WorkerCredentialRef, []string) error { calls++; return nil })
		if err == nil || calls != 0 {
			t.Fatal("tampered header/scope reached current authority", err)
		}
	}
	candidate := DispatchCandidate{&valid}
	f.codec.budget.StoredBytes = len(valid.header)
	if err := f.codec.BootstrapDispatch(f.context, candidate, f.authorizeDispatch, f.authorize); err != nil {
		t.Fatal("exact encrypted-header budget refused", err)
	}
	f.codec.budget.StoredBytes--
	if err := f.codec.BootstrapDispatch(f.context, candidate, f.authorizeDispatch, f.authorize); !errors.Is(err, ErrMessageBudget) {
		t.Fatal("encrypted-header budget ignored", err)
	}
	f.codec.budget = DefaultCodecBudget()
	f.codec.budget.HeaderBytes = 1
	if err := f.codec.BootstrapDispatch(f.context, candidate, f.authorizeDispatch, f.authorize); !errors.Is(err, ErrMessageBudget) {
		t.Fatal("decoded minimal-header budget ignored", err)
	}
	f.codec.budget = DefaultCodecBudget()
	canceled, cancel := context.WithCancel(f.context)
	cancel()
	if err := f.codec.BootstrapDispatch(canceled, candidate, f.authorizeDispatch, f.authorize); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled header bootstrap continued", err)
	}
	if err := (*Codec)(nil).BootstrapDispatch(f.context, candidate, f.authorizeDispatch, f.authorize); !errors.Is(err, ErrMessageUnavailable) {
		t.Fatal("nil codec entered crypto", err)
	}
}

func TestDispatchHeaderBootstrapRequiresCurrentOperationalAuthority(t *testing.T) {
	f := newMessageCodecFixture(t)
	sealed := f.seal(t, []byte(`{"q":"closed source"}`))
	candidate := DispatchCandidate{&dispatchCandidate{scope: f.scope, header: sealed.parts.header}}
	open := f.codec.open
	opens := 0
	f.codec.open = func(ctx context.Context, tenant, value string, aad []byte) ([]byte, error) {
		opens++
		return open(ctx, tenant, value, aad)
	}
	if err := f.codec.BootstrapDispatch(f.context, candidate, nil, f.authorize); !errors.Is(err, ErrMessageDenied) || opens != 0 {
		t.Fatal("candidate possession replaced current operational authority", err)
	}
	calls := 0
	lateDeny := func(context.Context, string, string) error {
		calls++
		if calls == 2 {
			return errors.New("private operational diagnostic")
		}
		return nil
	}
	if err := f.codec.BootstrapDispatch(f.context, candidate, lateDeny, f.authorize); !errors.Is(err, ErrMessageDenied) || calls != 2 || opens != 1 || strings.Contains(err.Error(), "private operational diagnostic") {
		t.Fatal("late internal authority loss admitted original provenance", err)
	}
	canceled, cancel := context.WithCancel(f.context)
	if err := f.codec.BootstrapDispatch(canceled, candidate, f.authorizeDispatch, func(context.Context, MessageScope, auth.WorkerCredentialRef, []string) error { cancel(); return nil }); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation during current-origin authorization returned success", err)
	}
}
