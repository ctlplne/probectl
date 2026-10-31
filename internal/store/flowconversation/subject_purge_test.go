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
	"math"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestSubjectPurgeRequiresExactPrivateSelectionAndCurrentAuthority(t *testing.T) {
	f := newMessageCodecFixture(t)
	stored := StoredMessage{&storedMessage{scope: f.scope, meta: inputMetadata(), kind: "input", position: 1, sealed: f.seal(t, []byte(`{"question":"private"}`))}}
	selection := subjectLeafSelection{pending: Invalidation{&invalidation{tenant: f.scope.TenantID, request: maintenanceRequestFixture(f), generation: 2}}, leaves: []StoredMessage{stored}}
	budget := CancellationBudget{Rows: 1, TimeLimit: time.Second}
	var journal *Journal
	called := false
	allow := func(context.Context, string) error { called = true; return nil }
	for _, ctx := range []context.Context{t.Context(), f.requestContext(t), tenancy.WithTenant(f.context, tenancy.ID(f.credentialID)), context.WithValue(f.context, subjectSourceLeaseKey{}, &subjectSourceLease{})} {
		if result, err := journal.purgeSubjectLeaf(ctx, selection, 0, budget, allow); result != (subjectPurgeBatch{}) || !errors.Is(err, ErrMessageDenied) {
			t.Fatal("request/source/foreign context reached deletion", err)
		}
	}
	for _, invalid := range []CancellationBudget{{}, {Rows: 1}, {TimeLimit: time.Second}, {Rows: -1, TimeLimit: time.Second}} {
		if result, err := journal.purgeSubjectLeaf(f.context, selection, 0, invalid, allow); result != (subjectPurgeBatch{}) || !errors.Is(err, ErrMessageBudget) {
			t.Fatal("invalid deletion resources reached SQL", err)
		}
	}
	for _, index := range []int{-1, 1} {
		if _, err := journal.purgeSubjectLeaf(f.context, selection, index, budget, allow); !errors.Is(err, ErrMessageDenied) {
			t.Fatal("unselected reference reached deletion", err)
		}
	}
	for _, mutate := range []func(*invalidation){
		func(p *invalidation) { p.tenant = f.credentialID },
		func(p *invalidation) { p.request.Kind = MaintenanceTenantErase },
		func(p *invalidation) { p.request.Binding = [32]byte{} },
		func(p *invalidation) { p.generation = 0 },
		func(p *invalidation) { p.generation = math.MaxUint64 },
	} {
		bad := *selection.pending.value
		mutate(&bad)
		selectionCopy := selection
		selectionCopy.pending = Invalidation{&bad}
		if _, err := journal.purgeSubjectLeaf(f.context, selectionCopy, 0, budget, allow); !errors.Is(err, ErrMessageDenied) {
			t.Fatal("another or unbound intent reached deletion", err)
		}
	}
	for _, mutate := range []func(*storedMessage){
		func(m *storedMessage) { m.scope.TenantID = f.credentialID },
		func(m *storedMessage) { m.position = 0 },
		func(m *storedMessage) { m.position = math.MaxUint64 },
		func(m *storedMessage) { m.scope.Revision = math.MaxUint64 },
		func(m *storedMessage) { m.meta.FrozenAt = time.Time{} },
		func(m *storedMessage) { m.kind = "caller_sql" },
		func(m *storedMessage) { m.sealed = SealedMessage{} },
	} {
		bad := *stored.value
		mutate(&bad)
		selectionCopy := selection
		selectionCopy.leaves = []StoredMessage{{&bad}}
		if _, err := journal.purgeSubjectLeaf(f.context, selectionCopy, 0, budget, allow); !errors.Is(err, ErrMessageIntegrity) {
			t.Fatal("invalid immutable pair reached deletion", err)
		}
	}
	if called {
		t.Fatal("invalid deletion invoked operational authority")
	}
	if _, err := journal.purgeSubjectLeaf(f.context, selection, 0, budget, nil); !errors.Is(err, ErrMessageDenied) {
		t.Fatal("missing independent current authority reached storage", err)
	}
	if _, err := journal.purgeSubjectLeaf(f.context, selection, 0, budget, allow); !errors.Is(err, ErrJournalUnavailable) || !called {
		t.Fatal("valid private reference did not reach unavailable storage", err)
	}
	value := subjectPurgeBatch{messagesDeleted: 1, jobsDeleted: 2}
	if _, err := json.Marshal(value); !errors.Is(err, errMessagePrivate) {
		t.Fatal("physical progress became a public completion receipt", err)
	}
	if err := json.Unmarshal([]byte(`{}`), new(subjectPurgeBatch)); !errors.Is(err, errMessagePrivate) {
		t.Fatal("JSON fabricated private physical progress", err)
	}
	if strings.Contains(fmt.Sprintf("%#v", value), "messagesDeleted") {
		t.Fatal("private progress leaked through formatting")
	}
}
