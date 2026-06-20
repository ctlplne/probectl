// SPDX-License-Identifier: LicenseRef-probectl-TBD

package docs

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/imfeelingtheagi/probectl/internal/config"
)

// TestFlowRetentionDefaultMatchesConfig keeps the operator-facing config table
// honest about the high-volume flow table's default retention. The control
// plane defaults to a finite 90-day TTL; `0` is an explicit keep-forever opt-out,
// not the default.
func TestFlowRetentionDefaultMatchesConfig(t *testing.T) {
	cfg, err := config.Load(func(string) string { return "" })
	if err != nil {
		t.Fatalf("load config defaults: %v", err)
	}
	b, err := os.ReadFile("configuration.md")
	if err != nil {
		t.Fatalf("read configuration.md: %v", err)
	}
	rowRE := regexp.MustCompile("(?m)^\\|\\s*`PROBECTL_FLOW_RETENTION_DAYS`\\s*\\|\\s*`([^`]+)`\\s*\\|([^\\n]+)$")
	match := rowRE.FindStringSubmatch(string(b))
	if match == nil {
		t.Fatal("configuration.md missing PROBECTL_FLOW_RETENTION_DAYS row")
	}
	gotDefault := strings.TrimSpace(match[1])
	wantDefault := fmt.Sprintf("%d", cfg.FlowRetentionDays)
	if gotDefault != wantDefault {
		t.Fatalf("documented PROBECTL_FLOW_RETENTION_DAYS default = %q, want actual config default %q", gotDefault, wantDefault)
	}
	meaning := match[2]
	if !strings.Contains(meaning, "`0` disables") || !strings.Contains(meaning, "keeps flows indefinitely") {
		t.Fatalf("configuration.md must state that 0 is an explicit keep-forever opt-out, row meaning: %s", strings.TrimSpace(meaning))
	}
}
