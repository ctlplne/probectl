// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"testing"

	"github.com/ctlplne/probectl/internal/store/flowstore"
)

func TestFlowFieldCutoffRequiresTheFirstExcludedOriginal(t *testing.T) {
	const measure = "bytes:total"
	row := func(value string) flowstore.PlanRow {
		return flowstore.PlanRow{Metrics: map[string]string{measure: value}}
	}
	rows := []flowstore.PlanRow{row("9007199254740995"), row("9007199254740993"), row("9007199254740993")}
	if provedFlowFieldCutoff(rows[:2], measure, 2) || provedFlowFieldCutoff(rows, measure, 2) {
		t.Fatal("an unavailable or tied boundary was taken as distinct membership")
	}
	rows[2] = row("9007199254740992")
	if !provedFlowFieldCutoff(rows, measure, 2) {
		t.Fatal("the first excluded original proved a strict cutoff above floating-point precision")
	}
	rows[2].Other = true
	if provedFlowFieldCutoff(rows, measure, 2) {
		t.Fatal("a remainder bucket was treated as an original source member")
	}
}
