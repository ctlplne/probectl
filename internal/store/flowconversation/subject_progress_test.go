// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flowconversation

import (
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"testing"
)

func TestSubjectProgressRequiresExactBoundedMonotoneCounts(t *testing.T) {
	previous := SubjectHistoryProgress{MessagesDeleted: 7, JobsDeleted: 9}
	got, err := advanceSubjectProgress(previous, 2, 3)
	if err != nil || got.MessagesDeleted != 9 || got.JobsDeleted != 12 || got.SourceEmpty || previous.MessagesDeleted != 7 {
		t.Fatal("durable counters did not advance exactly", err)
	}
	for _, v := range []struct {
		p    SubjectHistoryProgress
		m, j int64
	}{
		{SubjectHistoryProgress{MessagesDeleted: -1}, 0, 0},
		{SubjectHistoryProgress{JobsDeleted: -1}, 0, 0},
		{previous, -1, 0}, {previous, 0, -1},
		{SubjectHistoryProgress{MessagesDeleted: math.MaxInt64}, 1, 0},
		{SubjectHistoryProgress{JobsDeleted: math.MaxInt64}, 0, 1},
		{SubjectHistoryProgress{SourceEmpty: true}, 0, 0},
	} {
		if _, err := advanceSubjectProgress(v.p, v.m, v.j); err == nil {
			t.Fatal("invalid progress or terminal source phase advanced")
		}
	}
	if _, err := json.Marshal(got); err == nil {
		t.Fatal("private progress became public JSON")
	}
	if err := json.Unmarshal([]byte(`{}`), new(SubjectHistoryProgress)); err == nil {
		t.Fatal("JSON fabricated private progress")
	}
	if strings.Contains(fmt.Sprintf("%+v", got), "MessagesDeleted") {
		t.Fatal("private progress leaked through formatting")
	}
}
