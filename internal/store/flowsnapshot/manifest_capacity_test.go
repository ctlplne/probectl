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
	"testing"
	"time"
)

func TestSnapshotsCompleteObjectManifestFollowsConfiguredAdmission(t *testing.T) {
	const count = 5000001
	service, repo, objects := fixtureService(t)
	replica := *service
	inputFor := func(marker string) Input {
		row := json.RawMessage(`{"` + marker + `":0}`)
		rows := make([]json.RawMessage, count)
		for i := range rows {
			rows[i] = row
		}
		return Input{Query: json.RawMessage(`{"row_limit":5000001}`),
			Header:   json.RawMessage(`{"marker":"` + marker + `"}`),
			Validity: json.RawMessage(`{"source":"raw"}`), Rows: rows,
			ValidUntil: time.Now().Add(time.Hour)}
	}
	for index, scope := range []Scope{redScope, {TenantID: blueTenant, Owner: redScope.Owner}} {
		marker := []string{"r", "b"}[index]
		input := inputFor(marker)
		page, err := service.Create(t.Context(), scope, []string{"flow.read", "ai.query"}, 5000, allowSnapshot,
			func(context.Context) (Input, error) { return input, nil })
		if err != nil {
			t.Fatal("complete admitted manifest still uses former metadata quota", err)
		}
		stored, err := repo.get(t.Context(), scope, page.SnapshotID)
		if err != nil || len(stored.Private) <= 65536 || stored.ChargedBytes < int64(len(stored.Private)) {
			t.Fatal("complete manifest did not exceed former quota with its full charge", err)
		}
		first := page
		seen := 0
		for {
			if page.Offset != seen || page.SelectedRows != count || string(page.Data) != string(input.Header) {
				t.Fatal("complete manifest lost its tenant header, population or offset")
			}
			for _, row := range page.Rows {
				if !bytes.Equal(row, input.Rows[0]) {
					t.Fatal("complete manifest disclosed a different tenant marker")
				}
				seen++
			}
			if page.NextCursor == "" {
				break
			}
			page, err = replica.Resume(t.Context(), scope, page.NextCursor, allowSnapshot)
			if err != nil {
				t.Fatal("complete manifest continuation refused", err)
			}
		}
		if seen != count {
			t.Fatal("complete manifest silently truncated selected rows", seen)
		}
		foreign := Scope{TenantID: blueTenant, Owner: scope.Owner}
		if scope.TenantID == blueTenant {
			foreign.TenantID = redTenant
		}
		for _, denied := range []Scope{foreign, {TenantID: scope.TenantID, Owner: "different-owner"}} {
			if _, err := replica.Resume(t.Context(), denied, first.NextCursor, allowSnapshot); !errors.Is(err, ErrNotFound) {
				t.Fatal("complete manifest crossed tenant or owner", err)
			}
		}
		low := replica
		low.config.ObjectBytes = 65536
		reads := objects.reads.Load()
		if _, err := low.Resume(t.Context(), scope, first.NextCursor, allowSnapshot); !errors.Is(err, ErrBudget) || objects.reads.Load() != reads {
			t.Fatal("lower manifest admission read an object or lost whole-operation refusal", err)
		}
		denial := errors.New("current source permission refused")
		if _, err := low.Resume(t.Context(), scope, first.NextCursor,
			func(context.Context, Scope, []string) error { return denial }); !errors.Is(err, denial) || objects.reads.Load() != reads {
			t.Fatal("manifest size diagnostic preceded current source authorization", err)
		}
	}
	// Individual compact row chunks fit 64 KiB; only their complete manifest
	// exceeds it. Admission must fail before reserve/publication/object writes.
	service.config.ObjectBytes = 65536
	puts := objects.puts.Load()
	_, err := service.Create(t.Context(), redScope, []string{"flow.read", "ai.query"}, 5000, allowSnapshot,
		func(context.Context) (Input, error) { return inputFor("r"), nil })
	if !errors.Is(err, ErrBudget) || objects.puts.Load() != puts || len(repo.items) != 2 {
		t.Fatal("low manifest admission published partial output or changed storage charge", err)
	}
}
