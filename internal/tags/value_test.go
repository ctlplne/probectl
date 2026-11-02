// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package tags

import (
	"strings"
	"testing"
)

func TestTagValuesUseCharacterReachAndFailClosedOnInvalidText(t *testing.T) {
	for _, value := range []string{strings.Repeat("x", 24000), strings.Repeat("🌐", 24000)} {
		assignment := Assignment{Scope: testScope(), TagID: tagID, TargetKind: "exporter",
			TargetID: testSubject().ID, Value: value, Source: "manual"}
		result, err := resolve(testScope(), 4, testSubject(), []Definition{testDefinition()}, []Assignment{assignment}, nil)
		if err != nil || len(result) != 1 || result[0].Value != value {
			t.Fatalf("full published character reach was rejected or altered: length=%d err=%v", len(value), err)
		}
		rule := Rule{Scope: testScope(), ID: ruleA, TagID: tagID, TargetKind: "exporter",
			Match: "name_pattern", NamePattern: "^edge-1$", Value: value}
		result, err = resolve(testScope(), 5, testSubject(), []Definition{testDefinition()}, nil, []Rule{rule})
		if err != nil || len(result) != 1 || result[0].Value != value {
			t.Fatalf("rule value lost the supported character reach: %v", err)
		}
	}
	for _, value := range []string{"", " padded", "padded ", "line\nbreak", "control\u0085", string([]byte{0xff}),
		strings.Repeat("x", 24001), strings.Repeat("🌐", 24001)} {
		if err := ValidateValue(value); err == nil {
			t.Fatalf("invalid/over-limit value accepted: bytes=%d", len(value))
		}
	}
}
