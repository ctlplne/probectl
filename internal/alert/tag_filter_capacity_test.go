// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package alert

import (
	"fmt"
	"testing"

	"github.com/ctlplne/probectl/internal/flow"
)

func TestTagFilterAcceptsCompleteBindingsAboveFormerVocabularyCount(t *testing.T) {
	filter := TagFilter{Version: TagFilterVersion, TargetKind: "test", OwnerUserID: "10000000-0000-4000-8000-000000000001", TagRevision: "1", AsOf: "2026-11-05T00:00:00Z", TagIDs: map[string]string{}, Filter: &flow.QueryFilterGroup{}}
	for i := 1; i <= 129; i++ {
		filter.TagIDs[fmt.Sprintf("tag.custom_%03d", i)] = fmt.Sprintf("20000000-0000-4000-8000-%012d", i)
	}
	if err := filter.Validate(); err != nil {
		t.Fatal("complete larger alert bindings refused", err)
	}
	filter.TagIDs["tag.wrong"] = "not-an-immutable-id"
	if err := filter.Validate(); err == nil {
		t.Fatal("larger vocabulary bypassed immutable ID validation")
	}
}
