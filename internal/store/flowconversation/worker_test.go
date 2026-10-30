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
	"github.com/ctlplne/probectl/internal/crypto"
)

func TestWorkerLeasePrivateScopeAndExactOriginBeforeStorage(t *testing.T) {
	f := newMessageCodecFixture(t)
	ctx := f.requestContext(t)
	id, err := historyIdentityFor(ctx)
	if err != nil {
		t.Fatal(err)
	}
	w := &Worker{id: f.credentialID, lease: time.Minute}
	lease := WorkLease{&workLease{identity: id, scope: f.scope, worker: w.id, job: f.credentialID, generation: 1, until: time.Now().Add(time.Minute)}}
	if lease.Scope() != f.scope || !lease.Until().After(time.Now()) {
		t.Fatal("private lease metadata lost")
	}
	if _, err := json.Marshal(lease); err == nil {
		t.Fatal("lease became a wire capability")
	}
	if err := json.Unmarshal([]byte(`{}`), &lease); err == nil {
		t.Fatal("wire lease was accepted")
	}
	if strings.Contains(fmt.Sprintf("%+v %#+v", lease, &lease), f.scope.TenantID) {
		t.Fatal("private lease leaked scope")
	}
	allow := func(context.Context, string, string, auth.WorkerCredentialRef) error { return nil }
	deny := func(context.Context, string, string, auth.WorkerCredentialRef) error { return ErrMessageDenied }
	if err := w.CheckLease(ctx, lease, allow); !errors.Is(err, ErrJournalUnavailable) {
		t.Fatal("healthy scope did not reach availability check", err)
	}
	if err := w.CheckLease(ctx, lease, deny); !errors.Is(err, ErrMessageDenied) {
		t.Fatal("current refusal reached storage", err)
	}
	if _, err := w.Renew(ctx, lease, nil); !errors.Is(err, ErrMessageDenied) {
		t.Fatal("missing authority renewed a lease", err)
	}
	other := &Worker{id: "different-instance"}
	if err := other.CheckLease(ctx, lease, allow); !errors.Is(err, ErrMessageDenied) {
		t.Fatal("another process adopted a private lease", err)
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
	if _, err := w.Renew(auth.WithPrincipal(ctx, p), lease, allow); !errors.Is(err, ErrMessageDenied) {
		t.Fatal("same-row successor adopted an old lease", err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if err := w.CheckLease(canceled, lease, allow); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled request reached storage", err)
	}
	if (WorkLease{}).Scope() != (MessageScope{}) || !(WorkLease{}).Until().IsZero() {
		t.Fatal("empty lease exposed metadata")
	}
	for _, duration := range []time.Duration{-1, 0, time.Nanosecond} {
		if _, err := NewWorker(nil, duration); !errors.Is(err, ErrMessageBudget) {
			t.Fatal("invalid lease duration accepted", err)
		}
	}
}
