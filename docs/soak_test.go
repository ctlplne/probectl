// SPDX-License-Identifier: LicenseRef-probectl-TBD

package docs

import (
	"os"
	"strings"
	"testing"
)

func TestSoakRunbookSamplesRealDriftSignals(t *testing.T) {
	scriptBytes, err := os.ReadFile("../scripts/soak.sh")
	if err != nil {
		t.Fatalf("read scripts/soak.sh: %v", err)
	}
	script := string(scriptBytes)

	for _, want := range []string{
		"CONTROL_PID",
		"CLICKHOUSE_URL",
		"SOAK_QUERY_P95_METRIC",
		"go_goroutines",
		"go_threads",
		"process_rss_bytes",
		"open_fds",
		"ch_active_parts",
		"consumer_lag",
		"query_p95_ms",
		"metric_or_blank",
		"SELECT count() FROM system.parts WHERE active",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("scripts/soak.sh missing real soak signal %q", want)
		}
	}
	if strings.Contains(script, `"0" "0" >> "$OUT"`) {
		t.Fatal("scripts/soak.sh must not hardcode ClickHouse parts and consumer lag as zero")
	}
}
