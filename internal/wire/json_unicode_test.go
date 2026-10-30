// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package wire

import (
	"context"
	"testing"
)

func TestExactJSONUnicodePreservesStringsAndRejectsSurrogateReplacement(t *testing.T) {
	for _, test := range []struct {
		raw  string
		want bool
	}{
		{`{"a":"plain é"}`, true}, {`{"a":"\ud83d\ude00"}`, true}, {`{"a":"\\ud800"}`, true},
		{`{"a":"\ud800"}`, false}, {`{"a":"\udc00"}`, false}, {`{"a":"\ud800\u0041"}`, false},
		{`{"a":"truncated`, false}, {string([]byte{255}), false},
	} {
		if got := ExactJSONUnicode(t.Context(), test.raw); got != test.want {
			t.Errorf("input=%q valid=%v want=%v", test.raw, got, test.want)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if ExactJSONUnicode(ctx, `{"a":"valid"}`) {
		t.Fatal("canceled exact-Unicode scan succeeded")
	}
}
