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

	"github.com/ctlplne/probectl/internal/auth"
)

func TestMessageCodecHeaderCheckNeverOpensSourceOrGrantsLaterOpen(t *testing.T) {
	f := newMessageCodecFixture(t)
	record := f.seal(t, []byte(`{"question":"private source"}`))
	base := f.codec.open
	checks, opens := 0, 0
	f.codec.open = func(ctx context.Context, tenant, stored string, aad []byte) ([]byte, error) {
		if stored == record.parts.payload {
			opens++
		}
		return base(ctx, tenant, stored, aad)
	}
	authorize := func(ctx context.Context, scope MessageScope, origin auth.WorkerCredentialRef, required []string) error {
		checks++
		return f.authorize(ctx, scope, origin, required)
	}
	if err := f.codec.CheckHeader(f.context, f.scope, record, authorize); err != nil || checks != 1 || opens != 0 {
		t.Fatal("header-only authorization reached source decryption", err)
	}
	denied := func(context.Context, MessageScope, auth.WorkerCredentialRef, []string) error { return ErrMessageDenied }
	if body, err := f.codec.Open(f.context, f.scope, record, denied); body != nil || !errors.Is(err, ErrMessageDenied) || opens != 0 {
		t.Fatal("header preflight became a later source capability", err)
	}
	if err := f.codec.CheckHeader(f.context, f.scope, record, nil); !errors.Is(err, ErrMessageIntegrity) {
		t.Fatal("header check accepted missing authorization", err)
	}
	foreign := f.scope
	foreign.Revision++
	if err := f.codec.CheckHeader(f.context, foreign, record, authorize); !errors.Is(err, ErrMessageIntegrity) || checks != 1 || opens != 0 {
		t.Fatal("foreign header binding reached current callback", err)
	}
	ctx, cancel := context.WithCancel(f.context)
	if err := f.codec.CheckHeader(ctx, f.scope, record, func(context.Context, MessageScope, auth.WorkerCredentialRef, []string) error { cancel(); return nil }); !errors.Is(err, context.Canceled) || opens != 0 {
		t.Fatal("canceled header-only preflight returned success", err)
	}
	if body, err := f.codec.Open(f.context, f.scope, record, authorize); err != nil || opens != 1 {
		t.Fatal("healthy fresh authorization cannot open source", err)
	} else {
		clear(body)
	}
}

func TestStoredMessagePrivateResourceAndOrderMetadata(t *testing.T) {
	f := newMessageCodecFixture(t)
	sealed := f.seal(t, []byte(`{"question":"owned metadata"}`))
	record := StoredMessage{&storedMessage{scope: f.scope, sealed: sealed, position: 7}}
	if record.Position() != 7 || record.StoredBytes() != len(sealed.parts.header)+len(sealed.parts.payload) || (StoredMessage{}).Position() != 0 || (StoredMessage{}).StoredBytes() != 0 {
		t.Fatal("private immutable order/resource metadata changed")
	}
}
