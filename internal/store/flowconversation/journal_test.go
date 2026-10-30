// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flowconversation

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func (f messageCodecFixture) requestContext(t *testing.T) context.Context {
	t.Helper()
	p, err := auth.WithWorkerCredential(&auth.Principal{TenantID: f.scope.TenantID, UserID: f.scope.OwnerID, ViaBearerToken: true}, f.origin)
	if err != nil {
		t.Fatal(err)
	}
	return auth.WithPrincipal(f.context, p)
}

func inputMetadata() InputMetadata {
	now := time.Now().UTC()
	return InputMetadata{FrozenAt: now, ExpiresAt: now.Add(time.Hour)}
}

func TestJournalPrepareExactInputFreezesCallerDataBeforeAuthority(t *testing.T) {
	f := newMessageCodecFixture(t)
	ctx := f.requestContext(t)
	body := []byte(`{"question":"bob@example.test","number":18446744073709551617,"unicode":"\ud83d\ude00"}`)
	expected := bytes.Clone(body)
	meta := inputMetadata()
	parentID, err := crypto.UUIDv4()
	if err != nil {
		t.Fatal(err)
	}
	meta.Parent = &Revision{MessageID: parentID, Revision: 7}
	requirements := []string{"metrics.read", "flow.read", "ai.query"}
	calls := 0
	prepared, err := f.codec.PrepareInput(ctx, f.scope, meta, requirements, body, func(ctx context.Context, scope MessageScope, origin auth.WorkerCredentialRef, required []string) error {
		calls++
		if err := f.authorize(ctx, scope, origin, required); err != nil {
			return err
		}
		clear(body)
		clear(requirements)
		clear(required)
		meta.Parent.Revision = 99
		return nil
	})
	if err != nil || prepared.input == nil || calls != 2 {
		t.Fatal("exact authenticated input preparation refused", err, calls)
	}
	if prepared.input.meta.Parent.Revision != 7 || prepared.input.meta.Parent.MessageID != parentID || prepared.input.scope != f.scope || !prepared.input.meta.FrozenAt.Equal(meta.FrozenAt) {
		t.Fatal("caller changed prepared immutable metadata")
	}
	got, err := f.codec.Open(ctx, f.scope, prepared.input.sealed, f.authorize)
	defer clear(got)
	if err != nil || !bytes.Equal(got, expected) {
		t.Fatal("callback changed the prepared source/dependency union", err)
	}
	if _, err := json.Marshal(prepared); !errors.Is(err, errMessagePrivate) {
		t.Fatal("prepared private input crossed JSON boundary", err)
	}
	if err := json.Unmarshal([]byte(`{}`), &prepared); !errors.Is(err, errMessagePrivate) {
		t.Fatal("public request constructed prepared private storage", err)
	}
	for _, value := range []any{prepared, &prepared, struct{ Private PreparedInput }{prepared}} {
		text := fmt.Sprintf("%#v %+v", value, value)
		if bytes.Contains([]byte(text), expected) || bytes.Contains([]byte(text), []byte(prepared.input.sealed.parts.payload)) {
			t.Fatal("prepared input formatting disclosed private source/storage")
		}
	}
}

func TestJournalPrepareScopeMetadataAndCurrentAuthorityRefuse(t *testing.T) {
	for _, fault := range []string{"no-principal", "no-origin", "foreign-owner", "foreign-tenant", "missing-time", "expired-policy", "self-parent", "bad-parent", "missing-authorize", "deny-before", "deny-after", "cancel-after", "over-budget"} {
		t.Run(fault, func(t *testing.T) {
			f := newMessageCodecFixture(t)
			ctx := f.requestContext(t)
			ctx, cancel := context.WithCancel(ctx)
			defer cancel()
			scope, meta := f.scope, inputMetadata()
			body := []byte(`{"q":"original"}`)
			want := ErrMessageIntegrity
			calls := 0
			authorize := AuthorizeMessage(func(context.Context, MessageScope, auth.WorkerCredentialRef, []string) error {
				calls++
				if fault == "deny-before" || fault == "deny-after" && calls == 2 {
					return errors.New("private authorization backend detail")
				}
				if fault == "cancel-after" && calls == 2 {
					cancel()
				}
				return nil
			})
			switch fault {
			case "no-principal":
				ctx = auth.WithPrincipal(ctx, nil)
				want = ErrMessageDenied
			case "no-origin":
				ctx = auth.WithPrincipal(ctx, &auth.Principal{TenantID: scope.TenantID, UserID: scope.OwnerID})
				want = ErrMessageDenied
			case "foreign-owner":
				scope.OwnerID = f.credentialID
				want = ErrMessageDenied
			case "foreign-tenant":
				ctx = tenancy.WithTenant(ctx, tenancy.ID(f.credentialID))
			case "missing-time":
				meta.FrozenAt = time.Time{}
			case "expired-policy":
				meta.ExpiresAt = meta.FrozenAt
			case "self-parent":
				meta.Parent = &Revision{MessageID: scope.MessageID, Revision: scope.Revision}
			case "bad-parent":
				meta.Parent = &Revision{MessageID: "invalid", Revision: 1}
			case "missing-authorize":
				authorize = nil
			case "deny-before", "deny-after":
				want = ErrMessageDenied
			case "cancel-after":
				want = context.Canceled
			case "over-budget":
				f.codec.budget.PlainBytes = len(body) - 1
				want = ErrMessageBudget
			}
			prepared, err := f.codec.PrepareInput(ctx, scope, meta, []string{"ai.query", "flow.read"}, body, authorize)
			if prepared.input != nil || !errors.Is(err, want) {
				t.Fatal("invalid/refused preparation returned private work or wrong error", err)
			}
			if fault == "deny-after" && calls != 2 {
				t.Fatal("post-seal authority refusal not exercised")
			}
		})
	}
}

func TestJournalCannotAdoptPreparedInputWithReplacementOrigin(t *testing.T) {
	f := newMessageCodecFixture(t)
	ctx := f.requestContext(t)
	prepared, err := f.codec.PrepareInput(ctx, f.scope, inputMetadata(), []string{"ai.query", "flow.read", "metrics.read"}, []byte(`{"q":"original"}`), f.authorize)
	if err != nil {
		t.Fatal(err)
	}
	hash, err := crypto.Random(32)
	if err != nil {
		t.Fatal(err)
	}
	ref, err := auth.CaptureWorkerCredential(auth.WorkerCredentialMCP, f.scope.TenantID, f.scope.OwnerID, f.credentialID, hash)
	clear(hash)
	if err != nil {
		t.Fatal(err)
	}
	p, err := auth.WithWorkerCredential(&auth.Principal{TenantID: f.scope.TenantID, UserID: f.scope.OwnerID, ViaBearerToken: true}, ref)
	if err != nil {
		t.Fatal(err)
	}
	var journal *Journal // Any storage access would return unavailable instead.
	if err := journal.AdmitInput(auth.WithPrincipal(ctx, p), prepared, f.authorize); !errors.Is(err, ErrMessageDenied) {
		t.Fatal("replacement same-row credential adopted earlier prepared work", err)
	}
	if err := journal.AdmitInput(ctx, prepared, f.authorize); !errors.Is(err, ErrJournalUnavailable) {
		t.Fatal("healthy exact-origin operation skipped availability check", err)
	}
	if err := journal.AdmitInput(ctx, PreparedInput{}, f.authorize); !errors.Is(err, ErrMessageDenied) {
		t.Fatal("empty prepared input selected storage", err)
	}
}
