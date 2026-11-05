// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flowsnapshot

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
)

func TestSnapshotsCompleteRowsPastFormerQuotaStayPrivateAcrossReplicas(t *testing.T) {
	const count = 50001
	blueScope := Scope{blueTenant, redScope.Owner}
	service, _, _ := fixtureService(t)
	replica := *service
	for _, scope := range []Scope{redScope, blueScope} {
		input := fixtureInput(count)
		input.Query = json.RawMessage(`{"table_rows":50001}`)
		page, err := service.Create(t.Context(), scope, []string{"flow.read", "ai.query"}, 4999, allowSnapshot, func(context.Context) (Input, error) { return input, nil })
		if err != nil {
			t.Fatal("complete snapshot still uses former selected row quota", err)
		}
		first := page
		seen := 0
		for {
			if page.SelectedRows != count || page.Offset != seen {
				t.Fatal("snapshot selected count or offset changed")
			}
			for _, row := range page.Rows {
				if string(row) != fmt.Sprintf(`{"group":{"src_addr":"host%05d"},"metrics":{"bytes:total":"18446744073709551616001"}}`, seen) {
					t.Fatal("snapshot exact original row changed", seen)
				}
				seen++
			}
			if page.NextCursor == "" {
				break
			}
			page, err = replica.Resume(t.Context(), scope, page.NextCursor, allowSnapshot)
			if err != nil {
				t.Fatal(err)
			}
		}
		if seen != count {
			t.Fatal("snapshot output truncated", seen)
		}
		foreign := blueScope
		if scope.TenantID == blueScope.TenantID {
			foreign = redScope
		}
		if _, err := replica.Resume(t.Context(), foreign, first.NextCursor, allowSnapshot); !errors.Is(err, ErrNotFound) {
			t.Fatal("foreign snapshot cursor admitted", err)
		}
	}
	service.config.SnapshotBytes = 1024
	if _, err := service.Create(t.Context(), redScope, []string{"flow.read", "ai.query"}, 4999, allowSnapshot, func(context.Context) (Input, error) { return fixtureInput(count), nil }); !errors.Is(err, ErrBudget) {
		t.Fatal("snapshot resource refusal lost", err)
	}
}
