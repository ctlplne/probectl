// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package tags_test

import (
	"errors"
	"testing"

	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/tags"
)

// A future native flow field must not silently become a tenant-defined tag
// key. The API uses the same tag definition validation as this snapshot.
func TestNativeFlowFieldsCannotBeShadowedByTenantTags(t *testing.T) {
	scope := tags.Scope{
		TenantID:  "11111111-1111-4111-8111-111111111111",
		ContextID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
	}
	for _, field := range flow.QueryFields() {
		t.Run(field.Name, func(t *testing.T) {
			_, err := tags.NewSnapshot(scope, 1, []tags.Definition{{
				TenantID: scope.TenantID,
				ID:       "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
				Key:      field.Name,
			}}, nil, nil)
			if !errors.Is(err, tags.ErrInvalid) {
				t.Fatalf("native query field %q admitted as a tenant tag key: %v", field.Name, err)
			}
		})
	}
}
