// SPDX-License-Identifier: LicenseRef-probectl-TBD

package flowstore

import (
	"testing"
	"time"
)

// CORRECT-002: flowRowID is the ReplacingMergeTree dedup key. A redelivered
// identical row must hash identically (so the duplicate collapses); any field
// that distinguishes two real flows must change the id (so real traffic is
// never collapsed).
func TestFlowRowIDDedupKey(t *testing.T) {
	ts := time.Unix(1_700_000_000, 0).UTC()
	base := Row{
		TenantID: "t-a", AgentID: "agent-1", Exporter: "10.0.0.1", ObsDomain: 1,
		TS: ts, SrcAddr: "10.1.1.1", DstAddr: "10.2.2.2", SrcPort: 1234, DstPort: 443,
		Protocol: "tcp", Bytes: 1500, Packets: 3, InIf: 2, OutIf: 5,
	}

	if flowRowID(base) != flowRowID(base) {
		t.Fatal("identical rows must produce the same dedup id")
	}

	// Each distinguishing field must change the id.
	for name, mutate := range map[string]func(*Row){
		"dst_port": func(r *Row) { r.DstPort = 444 },
		"bytes":    func(r *Row) { r.Bytes = 1600 },
		"ts":       func(r *Row) { r.TS = ts.Add(time.Second) },
		"src_addr": func(r *Row) { r.SrcAddr = "10.1.1.9" },
		"tenant":   func(r *Row) { r.TenantID = "t-b" },
	} {
		r := base
		mutate(&r)
		if flowRowID(r) == flowRowID(base) {
			t.Errorf("changing %s did not change the dedup id (real flows would be collapsed)", name)
		}
	}
}
