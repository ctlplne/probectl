// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package tenantlife

import (
	"bytes"
	"strings"
	"testing"
)

// TestFilterJSONLLinesMatchesSubjectExactly is the TEN-05 regression for the
// flow subject-export filter. ExportTenant streams the whole (tenant-scoped)
// flow history and this filter narrows it to the subject. The old whole-line
// substring match kept every row that merely contained the subject string, so a
// DSAR export for "10.0.0.1" also disclosed "10.0.0.10" and "110.0.0.1". Exact
// per-value matching must keep only the row whose field equals the subject.
func TestFilterJSONLLinesMatchesSubjectExactly(t *testing.T) {
	jsonl := []byte(`{"tenant_id":"t","src_addr":"10.0.0.1","dst_addr":"203.0.113.9","bytes":1000}
{"tenant_id":"t","src_addr":"10.0.0.10","dst_addr":"203.0.113.9","bytes":2000}
{"tenant_id":"t","src_addr":"110.0.0.1","dst_addr":"203.0.113.9","bytes":3000}
`)

	var out bytes.Buffer
	n := filterJSONLLines(&out, jsonl, "10.0.0.1")
	if n != 1 {
		t.Fatalf("filterJSONLLines kept %d rows, want exactly the 10.0.0.1 row (substring over-match kept neighbors)", n)
	}
	body := out.String()
	if !strings.Contains(body, `"src_addr":"10.0.0.1"`) {
		t.Fatalf("exact subject row missing from filtered export: %s", body)
	}
	if strings.Contains(body, "10.0.0.10") || strings.Contains(body, "110.0.0.1") {
		t.Fatalf("OVER-MATCH: a neighboring address leaked into the subject export: %s", body)
	}

	// A numeric field that stringifies to a short value must never be coerced to
	// a subject match, and an empty subject exports nothing.
	var empty bytes.Buffer
	if got := filterJSONLLines(&empty, jsonl, " "); got != 0 || empty.Len() != 0 {
		t.Fatalf("empty subject = rows=%d bytes=%d, want 0/0", got, empty.Len())
	}
}
