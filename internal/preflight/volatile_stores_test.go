// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package preflight

import (
	"strings"
	"testing"
)

// PLAT-01/RTO-04: `preflight --strict` must exit non-zero when telemetry is
// memory-backed and the volatility is unacknowledged.
func TestCheckVolatileStores(t *testing.T) {
	if f := CheckVolatileStores(nil, false); f.Severity != OK {
		t.Errorf("all-durable must be OK, got %v (%s)", f.Severity, f.Detail)
	}

	warn := CheckVolatileStores([]string{"PROBECTL_BUS_MODE=memory", "PROBECTL_TSDB_MODE=memory"}, false)
	if warn.Severity != Warn {
		t.Fatalf("unacknowledged volatile must Warn (gates --strict), got %v", warn.Severity)
	}
	if !strings.Contains(warn.Detail, "PROBECTL_BUS_MODE=memory") {
		t.Errorf("the warning must name the volatile planes: %q", warn.Detail)
	}
	if !strict([]Finding{warn}) {
		t.Error("a volatile Warn must make --strict exit non-zero")
	}

	info := CheckVolatileStores([]string{"PROBECTL_BUS_MODE=memory"}, true)
	if info.Severity != Info {
		t.Fatalf("acknowledged volatile must be Info (exit 0), got %v", info.Severity)
	}
	if strict([]Finding{info}) {
		t.Error("an acknowledged (Info) volatile finding must not gate --strict")
	}
}
