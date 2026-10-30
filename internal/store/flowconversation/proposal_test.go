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
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/crypto"
)

func TestPrepareProposalRequiresOriginalOriginCompleteUnionAndFrozenInput(t *testing.T) {
	for _, fault := range []string{"healthy", "missing-inherited-permission", "different-origin", "different-clock", "longer-deadline", "missing-deadline", "deny-after-seal", "already-proposed"} {
		t.Run(fault, func(t *testing.T) {
			f := newMessageCodecFixture(t)
			ctx := f.requestContext(t)
			identity, err := historyIdentityFor(ctx)
			if err != nil {
				t.Fatal(err)
			}
			input := StoredMessage{&storedMessage{scope: f.scope, meta: inputMetadata(), kind: "input", sealed: f.seal(t, []byte(`{"question":"original private source"}`))}}
			lease := WorkLease{&workLease{identity: identity, scope: f.scope, until: time.Now().Add(time.Minute)}}
			scope := f.scope
			scope.MessageID, err = crypto.UUIDv4()
			if err != nil {
				t.Fatal(err)
			}
			meta := input.Metadata()
			meta.Parent = &Revision{MessageID: f.scope.MessageID, Revision: f.scope.Revision}
			required := []string{"ai.query", "flow.read", "metrics.read"}
			body := []byte(`{"proposal":"private prepared source"}`)
			original := bytes.Clone(body)
			switch fault {
			case "missing-inherited-permission":
				required = required[:2]
			case "different-origin":
				hash, err := crypto.Random(32)
				if err != nil {
					t.Fatal(err)
				}
				ref, err := auth.CaptureWorkerCredential(auth.WorkerCredentialMCP, f.scope.TenantID, f.scope.OwnerID, f.credentialID, hash)
				clear(hash)
				if err != nil {
					t.Fatal(err)
				}
				input.value.sealed, err = f.codec.Seal(ctx, f.scope, ref, required, []byte(`{"question":"different origin"}`))
				if err != nil {
					t.Fatal(err)
				}
			case "different-clock":
				meta.FrozenAt = meta.FrozenAt.Add(time.Nanosecond)
			case "longer-deadline":
				meta.ExpiresAt = meta.ExpiresAt.Add(time.Second)
			case "missing-deadline":
				meta.ExpiresAt = time.Time{}
			case "already-proposed":
				lease.value.proposal = &Revision{MessageID: scope.MessageID, Revision: 1}
			}
			seals, opens := 0, 0
			seal, open := f.codec.seal, f.codec.open
			f.codec.seal = func(ctx context.Context, tenant string, plain, aad []byte) (string, error) {
				seals++
				return seal(ctx, tenant, plain, aad)
			}
			f.codec.open = func(ctx context.Context, tenant, cipher string, aad []byte) ([]byte, error) {
				opens++
				if !bytes.Equal(aad, f.scope.aad('h')) {
					t.Fatal("preparation opened source-bearing input payload")
				}
				return open(ctx, tenant, cipher, aad)
			}
			authorize := func(ctx context.Context, _ MessageScope, ref auth.WorkerCredentialRef, got []string) error {
				clear(body) // External callbacks cannot change the frozen proposal.
				if fault == "deny-after-seal" && seals > 0 {
					return ErrMessageDenied
				}
				return f.authorize(ctx, f.scope, ref, got)
			}
			prepared, err := f.codec.PrepareProposal(ctx, lease, input, scope, meta, required, body, authorize)
			if fault != "healthy" {
				if err == nil || prepared.value != nil || fault != "deny-after-seal" && seals != 0 {
					t.Fatal("invalid proposal escaped or encrypted before validation", err, seals)
				}
				return
			}
			if err != nil || prepared.value == nil || seals != 2 || opens != 1 {
				t.Fatal("healthy proposal preparation failed", err, seals, opens)
			}
			if _, err := json.Marshal(prepared); err == nil {
				t.Fatal("prepared proposal became public")
			}
			if err := json.Unmarshal([]byte(`{}`), &prepared); err == nil {
				t.Fatal("prepared proposal accepted wire input")
			}
			if strings.Contains(fmt.Sprintf("%+v %#+v", prepared, &prepared), scope.TenantID) {
				t.Fatal("prepared proposal leaked private bindings")
			}
			if !slices.Equal(prepared.value.required, []string{"ai.query", "flow.read", "metrics.read"}) {
				t.Fatal("prepared proposal lost inherited requirements")
			}
			f.codec.open = open
			got, err := f.codec.Open(ctx, scope, prepared.value.sealed, func(ctx context.Context, _ MessageScope, ref auth.WorkerCredentialRef, got []string) error {
				return f.authorize(ctx, f.scope, ref, got)
			})
			if err != nil || !bytes.Equal(got, original) {
				t.Fatal("callback changed the frozen proposal body", err)
			}
			clear(got)
			var worker *Worker
			if _, err := worker.PublishProposal(ctx, WorkLease{}, prepared, authorize); !errors.Is(err, ErrMessageDenied) {
				t.Fatal("empty lease reached proposal storage", err)
			}
		})
	}
}
