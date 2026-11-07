// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flowsnapshot

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
)

func TestSnapshotsKeepWholeSourceValidityUnderConfiguredAdmission(t *testing.T) {
	const count = 50_000
	service, repo, objects := fixtureService(t)
	expected := map[Scope]json.RawMessage{}
	service.validate = func(_ context.Context, got Scope, body json.RawMessage) error {
		if !bytes.Equal(body, expected[got]) {
			return ErrIntegrity
		}
		return nil
	}
	replica := *service
	for _, scope := range []Scope{redScope, {TenantID: blueTenant, Owner: redScope.Owner}} {
		selectors := make([]string, count)
		for i := range selectors {
			selectors[i] = fmt.Sprintf("%s/original-flow-%d/1700000000987654321", scope.TenantID, i)
		}
		validity, err := json.Marshal(struct{ Selectors []string }{selectors})
		if err != nil || len(validity) <= 8192 {
			t.Fatal("source validity fixture lacks its complete intended workload", err)
		}
		expected[scope] = validity
		input := fixtureInput(2)
		input.Validity = validity
		first, err := service.Create(t.Context(), scope, []string{"flow.read", "ai.query"}, 1, allowSnapshot, func(context.Context) (Input, error) { return input, nil })
		if err != nil {
			t.Fatal("whole admitted source validity still uses the former fixed ceiling", len(validity), err)
		}
		stored, err := repo.get(t.Context(), scope, first.SnapshotID)
		if err != nil || stored.ChargedBytes <= int64(len(validity)) || bytes.Contains([]byte(stored.Private), []byte(selectors[count-1])) {
			t.Fatal("complete source validity was uncharged or retained in plaintext", err)
		}
		if second, err := replica.Resume(t.Context(), scope, first.NextCursor, allowSnapshot); err != nil || len(second.Rows) != 1 || !bytes.Equal(second.Rows[0], input.Rows[1]) {
			t.Fatal("replica lost the complete original source-policy receipt", err)
		}
		foreign := Scope{TenantID: blueTenant, Owner: scope.Owner}
		if scope.TenantID == blueTenant {
			foreign = redScope
		}
		before := objects.reads.Load()
		if _, err := replica.Resume(t.Context(), foreign, first.NextCursor, allowSnapshot); err == nil || objects.reads.Load() != before {
			t.Fatal("foreign source validity reached another tenant's objects", err)
		}
		denied := replica
		denied.validate = func(context.Context, Scope, json.RawMessage) error { return ErrNotFound }
		before = objects.reads.Load()
		if _, err := denied.Resume(t.Context(), scope, first.NextCursor, allowSnapshot); !errors.Is(err, ErrNotFound) || objects.reads.Load() != before {
			t.Fatal("invalid current source validity reached retained objects", err)
		}
		limited := *service
		limited.config.ObjectBytes = int64(len(validity) - 1)
		if _, err := limited.Create(t.Context(), scope, []string{"flow.read", "ai.query"}, 1, allowSnapshot, func(context.Context) (Input, error) { return input, nil }); !errors.Is(err, ErrBudget) {
			t.Fatal("source validity ignored configured object admission", err)
		}
	}
	t.Log("simulation: complete 50000-selector source receipts per tenant, actual envelope encryption and native object repository, byte charge/replica/current refusal/sibling; Postgres proof remains separate")
}
