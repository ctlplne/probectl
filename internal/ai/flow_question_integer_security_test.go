// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package ai

import (
	"math/big"
	"strconv"
	"testing"
)

func TestQuestionIntegerPreservesRepresentableReachWithoutWrapping(t *testing.T) {
	maximum := int(^uint(0) >> 1)
	overflow := new(big.Int).Add(big.NewInt(int64(maximum)), big.NewInt(1)).String()
	for _, item := range []struct {
		text  string
		want  int
		valid bool
	}{
		{"0", 0, true}, {"2147483647", 2147483647, true}, {strconv.Itoa(maximum), maximum, true},
		{overflow, 0, false}, {"18446744073709551615", 0, false}, {"-1", 0, false},
	} {
		tokens, err := lexFlowQuestion(t.Context(), item.text, DefaultFlowQuestionBudget())
		if err != nil {
			if item.valid {
				t.Fatal(err)
			}
			continue
		}
		cursor := questionCursor{ctx: t.Context(), tokens: tokens, budget: DefaultFlowQuestionBudget()}
		value, err := cursor.integer()
		if (err == nil) != item.valid || (item.valid && value != item.want) {
			t.Fatal("question integer wrapped or narrowed representable input", item.text, value, err)
		}
	}
}
