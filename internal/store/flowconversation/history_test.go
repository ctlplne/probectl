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
	"math"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func (f messageCodecFixture) authorizeHistory(_ context.Context, tenant, owner string, origin auth.WorkerCredentialRef) error {
	if tenant != f.scope.TenantID || owner != f.scope.OwnerID || !origin.MatchesStored(auth.WorkerCredentialMCP, tenant, owner, f.credentialID, f.storedHash) {
		return ErrMessageDenied
	}
	return nil
}

func TestHistoryBoundaryRefusalsBeforeSQL(t *testing.T) {
	f := newMessageCodecFixture(t)
	ctx := f.requestContext(t)
	var journal *Journal
	key := Revision{MessageID: f.scope.MessageID, Revision: 1}
	for _, revision := range []Revision{{}, {MessageID: "bad", Revision: 1}, {MessageID: key.MessageID, Revision: math.MaxUint64}} {
		if got, err := journal.Lookup(ctx, f.scope.ConversationID, revision, 1000, f.authorizeHistory); got.value != nil || !errors.Is(err, ErrJournalConflict) {
			t.Fatal("invalid immutable key reached unavailable SQL port", err)
		}
	}
	if got, err := journal.Lookup(ctx, f.scope.ConversationID, key, 0, f.authorizeHistory); got.value != nil || !errors.Is(err, ErrMessageBudget) {
		t.Fatal("nonpositive lookup resource reached SQL", err)
	}
	if got, err := journal.Lookup(ctx, f.scope.ConversationID, key, 1000, nil); got.value != nil || !errors.Is(err, ErrMessageDenied) {
		t.Fatal("missing current history authority reached SQL", err)
	}
	for _, bad := range []context.Context{f.context, tenancy.WithTenant(ctx, tenancy.ID(f.credentialID)), auth.WithPrincipal(ctx, &auth.Principal{TenantID: f.scope.TenantID, UserID: f.scope.OwnerID})} {
		if got, err := journal.Lookup(bad, f.scope.ConversationID, key, 1000, f.authorizeHistory); got.value != nil || !errors.Is(err, ErrMessageDenied) {
			t.Fatal("missing/foreign private identity selected history SQL", err)
		}
	}
	if got, err := journal.Page(ctx, f.scope.ConversationID, nil, HistoryBudget{}, f.authorizeHistory); got.Messages != nil || !errors.Is(err, ErrMessageBudget) {
		t.Fatal("nonpositive page resource selected SQL", err)
	}
	for _, cursor := range []*HistoryCursor{
		{},
		{&historyWindow{tenant: f.scope.TenantID, owner: f.credentialID, conversation: f.scope.ConversationID, after: 1, upper: 2, generation: 1, validUntil: time.Now().Add(time.Hour)}},
		{&historyWindow{tenant: f.scope.TenantID, owner: f.scope.OwnerID, conversation: f.scope.ConversationID, after: 2, upper: 2, generation: 1, validUntil: time.Now().Add(time.Hour)}},
	} {
		if got, err := journal.Page(ctx, f.scope.ConversationID, cursor, HistoryBudget{Rows: 1, Bytes: 1000}, f.authorizeHistory); got.Messages != nil || err == nil || errors.Is(err, ErrJournalUnavailable) {
			t.Fatal("invalid/foreign cursor selected SQL", err)
		}
	}
	if got, err := journal.Lookup(ctx, f.scope.ConversationID, key, 1000, f.authorizeHistory); got.value != nil || !errors.Is(err, ErrJournalUnavailable) {
		t.Fatal("healthy scoped lookup did not reach availability check", err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if got, err := journal.Page(canceled, f.scope.ConversationID, nil, HistoryBudget{Rows: 1, Bytes: 1000}, f.authorizeHistory); got.Messages != nil || !errors.Is(err, context.Canceled) {
		t.Fatal("canceled history selected storage", err)
	}
}

func TestHistoryPrivateObjectsCannotCrossJSON(t *testing.T) {
	for _, value := range []any{StoredMessage{}, HistoryCursor{}, HistoryPage{}} {
		if _, err := json.Marshal(value); !errors.Is(err, errMessagePrivate) {
			t.Fatal("private history reference crossed JSON boundary", err)
		}
	}
	if err := json.Unmarshal([]byte(`{}`), new(StoredMessage)); !errors.Is(err, errMessagePrivate) {
		t.Fatal("public JSON constructed stored source reference", err)
	}
	if err := json.Unmarshal([]byte(`{}`), new(HistoryCursor)); !errors.Is(err, errMessagePrivate) {
		t.Fatal("public JSON constructed private history continuation", err)
	}
	var empty StoredMessage
	if empty.Scope() != (MessageScope{}) || !empty.Metadata().FrozenAt.IsZero() || empty.Kind() != "" || empty.Ciphertext().parts != nil {
		t.Fatal("empty private history reference acquired data")
	}
}
