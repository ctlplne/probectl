// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flowconversation

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestSubjectSelectionRequiresPositiveResourcesAndTypedMatcher(t *testing.T) {
	var j *Journal
	for _, budget := range []HistoryBudget{{}, {Rows: 1}, {Bytes: 1}, {Rows: -1, Bytes: 1}} {
		got, err := j.selectSubjectLeaves(t.Context(), nil, Invalidation{}, budget, nil, nil)
		if !errors.Is(err, ErrMessageBudget) || got.exhausted || got.scanned != 0 || len(got.leaves) != 0 {
			t.Fatal("invalid resource budget reached source admission", err)
		}
	}
	if _, err := j.selectSubjectLeaves(t.Context(), nil, Invalidation{}, HistoryBudget{Rows: 1, Bytes: 1}, nil, nil); !errors.Is(err, ErrMessageDenied) {
		t.Fatal("missing typed matcher reached source admission", err)
	}
	selection := subjectLeafSelection{leaves: []StoredMessage{{value: &storedMessage{scope: MessageScope{TenantID: "private-tenant"}}}}}
	if _, err := json.Marshal(selection); !errors.Is(err, errMessagePrivate) {
		t.Fatal("private selected references crossed JSON", err)
	}
	if err := json.Unmarshal([]byte(`{}`), new(subjectLeafSelection)); !errors.Is(err, errMessagePrivate) {
		t.Fatal("JSON fabricated a private selection", err)
	}
	if strings.Contains(fmt.Sprintf("%#v", selection), "private-tenant") {
		t.Fatal("private selected references leaked through formatting")
	}
}

func TestSubjectParentEdgeRequiresEveryImmediateBinding(t *testing.T) {
	f := newMessageCodecFixture(t)
	parent := StoredMessage{&storedMessage{scope: f.scope, position: 2, meta: InputMetadata{FrozenAt: time.Unix(100, 0)}}}
	childScope := f.scope
	childScope.MessageID = f.credentialID
	child := StoredMessage{&storedMessage{scope: childScope, position: 3, meta: InputMetadata{FrozenAt: time.Unix(101, 0), Parent: &Revision{MessageID: parent.Scope().MessageID, Revision: parent.Scope().Revision}}}}
	if !subjectParentEdge(child, parent) {
		t.Fatal("valid immediate parent refused")
	}
	for _, mutate := range []func(*storedMessage){
		func(p *storedMessage) { p.scope.TenantID = f.credentialID },
		func(p *storedMessage) { p.scope.OwnerID = f.credentialID },
		func(p *storedMessage) { p.scope.ConversationID = f.credentialID },
		func(p *storedMessage) { p.scope.MessageID = f.credentialID },
		func(p *storedMessage) { p.scope.Revision++ },
		func(p *storedMessage) { p.position = 0 },
		func(p *storedMessage) { p.position = child.Position() },
		func(p *storedMessage) { p.scope.Epoch = 0 },
		func(p *storedMessage) { p.scope.Epoch = child.Scope().Epoch + 1 },
		func(p *storedMessage) { p.meta.FrozenAt = child.Metadata().FrozenAt.Add(time.Nanosecond) },
	} {
		bad := *parent.value
		mutate(&bad)
		if subjectParentEdge(child, StoredMessage{&bad}) {
			t.Fatal("mismatched/reversed immediate parent admitted")
		}
	}
	if subjectParentEdge(StoredMessage{}, parent) || subjectParentEdge(child, StoredMessage{}) {
		t.Fatal("missing ancestor admitted")
	}
	// Both fit below the original leaf; their intermediate edge still inverts.
	grandparent := *parent.value
	grandparent.position = 1
	grandparent.scope.MessageID = f.scope.OwnerID
	grandparent.meta.FrozenAt = time.Unix(100, 500)
	parent.value.meta.Parent = &Revision{MessageID: grandparent.scope.MessageID, Revision: grandparent.scope.Revision}
	if subjectParentEdge(parent, StoredMessage{&grandparent}) {
		t.Fatal("grandparent was compared only against the original leaf")
	}
}
