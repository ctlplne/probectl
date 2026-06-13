// SPDX-License-Identifier: LicenseRef-probectl-TBD

package pipeline

import (
	"os"
	"strings"
	"testing"

	resultv1 "github.com/imfeelingtheagi/probectl/internal/gen/probectl/result/v1"
)

// CORRECT-002: the result_id field was documented as "the dedup key for
// append-only row stores: a ReplacingMergeTree keyed on result_id collapses the
// duplicate" — but probe results are converted to TSDB time series
// (ResultToSeries), never written to a ReplacingMergeTree, so for results that
// claim was false: result_id is computed and discarded. This contract test
// pins the corrected reality so the doc and the code cannot drift apart again.
func TestResultDedupContractMatchesCode(t *testing.T) {
	// (1) The result conversion must NOT emit result_id as a series label — it is
	// not a TSDB dedup mechanism (TSDB idempotency is (series, timestamp)). If a
	// future change starts shipping result_id into the TSDB labels, that is a
	// cardinality explosion AND a false-dedup signal; fail loudly.
	r := &resultv1.Result{
		TenantId: "t1", AgentId: "a1", CanaryType: "icmp", Success: true,
		ResultId: "rid-deadbeef",
	}
	for _, s := range ResultToSeries(r) {
		if _, ok := s.Labels["result_id"]; ok {
			t.Fatalf("ResultToSeries emitted a result_id label on %s — results are TSDB series, result_id is not a dedup key here", s.Metric)
		}
	}

	// (2) The proto field doc must no longer claim result_id is the result
	// ReplacingMergeTree dedup key. It must state the TSDB-idempotency reality.
	doc, err := os.ReadFile("../../proto/probectl/result/v1/result.proto")
	if err != nil {
		t.Skipf("proto source not readable from here: %v", err)
	}
	src := string(doc)
	// The corrected doc states results are TSDB series, not RMT rows.
	if !strings.Contains(src, "stored as TIME SERIES in") {
		t.Error("result_id proto doc does not state results are stored as TIME SERIES (the real mechanism)")
	}
	// And it must not reassert the false "ReplacingMergeTree keyed on result_id
	// collapses" claim FOR RESULTS (the original wording).
	if strings.Contains(src, "ReplacingMergeTree keyed on result_id collapses") {
		t.Error("result_id proto doc still asserts the false result_id-keyed ReplacingMergeTree dedup for results")
	}
}
