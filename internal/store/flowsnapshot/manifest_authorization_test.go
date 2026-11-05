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
	"testing"
)

// withheldManifestRepository models the bounded SQL projection: public control
// fields remain, but the private authority receipt has not entered the process.
type withheldManifestRepository struct{ repository }

func (r withheldManifestRepository) get(ctx context.Context, scope Scope, id string) (manifest, error) {
	m, err := r.repository.get(ctx, scope, id)
	if err != nil {
		return m, err
	}
	m.Private = ""
	return m, ErrBudget
}

func TestSnapshotsUnreadableMetadataDoesNotDiscloseRevokedSource(t *testing.T) {
	for _, scope := range []Scope{redScope, {TenantID: blueTenant, Owner: redScope.Owner}} {
		t.Run(scope.TenantID, func(t *testing.T) {
			service, repo, objects := fixtureService(t)
			first := createFixture(t, service, scope, 2, 1)
			// The caller still has global flow/AI grants, but has lost the
			// context-specific access recorded inside the encrypted receipt.
			service.validate = func(context.Context, Scope, json.RawMessage) error { return ErrNotFound }
			reads := objects.reads.Load()
			if _, err := service.Resume(t.Context(), scope, first.NextCursor, allowSnapshot); !errors.Is(err, ErrNotFound) {
				t.Fatal("current source revocation did not withdraw the snapshot", err)
			}
			for _, projection := range []string{"private-field-admission", "sql-withheld-field"} {
				t.Run(projection, func(t *testing.T) {
					limited := *service
					if projection == "sql-withheld-field" {
						limited.repo = withheldManifestRepository{repo}
					} else {
						limited.config.ObjectBytes = 1
					}
					if _, err := limited.Resume(t.Context(), scope, first.NextCursor, allowSnapshot); !errors.Is(err, ErrNotFound) {
						t.Fatal("unreadable metadata disclosed a revoked source through its admission error", err)
					}
					called := false
					err := limited.Walk(t.Context(), scope, first.SnapshotID, allowSnapshot,
						func(Header) error { called = true; return nil }, func([]json.RawMessage) error { called = true; return nil })
					if !errors.Is(err, ErrNotFound) || called || objects.reads.Load() != reads {
						t.Fatal("unreadable snapshot exposed output or read source objects", err)
					}
					foreign := Scope{TenantID: blueTenant, Owner: scope.Owner}
					if scope.TenantID == blueTenant {
						foreign.TenantID = redTenant
					}
					for _, other := range []Scope{foreign, {TenantID: scope.TenantID, Owner: "other-owner"}} {
						if _, err := limited.Resume(t.Context(), other, first.NextCursor, allowSnapshot); !errors.Is(err, ErrNotFound) {
							t.Fatal("unreadable snapshot crossed tenant or owner", err)
						}
					}
					denied := errors.New("current global grant denied")
					if _, err := limited.Resume(t.Context(), scope, first.NextCursor,
						func(context.Context, Scope, []string) error { return denied }); !errors.Is(err, denied) {
						t.Fatal("unreadable snapshot bypassed current global authorization", err)
					}
				})
			}
		})
	}
}
