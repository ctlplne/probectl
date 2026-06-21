// SPDX-License-Identifier: LicenseRef-probectl-TBD

package docs

import (
	"fmt"
	"os"
	"regexp"
	"sort"
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

// TestControlPlaneEnvKeysHaveConfigurationRows keeps the page-level promise
// honest: every PROBECTL_* key the control-plane config loader reads gets a
// real markdown table row, not just a stray mention in prose.
func TestControlPlaneEnvKeysHaveConfigurationRows(t *testing.T) {
	configCode, err := os.ReadFile("../internal/config/config.go")
	if err != nil {
		t.Fatalf("read internal/config/config.go: %v", err)
	}
	doc, err := os.ReadFile("configuration.md")
	if err != nil {
		t.Fatalf("read configuration.md: %v", err)
	}

	loaderKeyRE := regexp.MustCompile("l\\.[A-Za-z0-9]+\\(\"(PROBECTL_[A-Z0-9_]+)\"")
	loaderKeys := map[string]struct{}{}
	for _, match := range loaderKeyRE.FindAllSubmatch(configCode, -1) {
		loaderKeys[string(match[1])] = struct{}{}
	}
	if len(loaderKeys) == 0 {
		t.Fatal("found no PROBECTL_* keys in internal/config/config.go")
	}

	rowKeyRE := regexp.MustCompile("(?m)^\\|\\s*`(PROBECTL_[A-Z0-9_]+)`\\s*\\|")
	rowKeys := map[string]struct{}{}
	for _, match := range rowKeyRE.FindAllSubmatch(doc, -1) {
		rowKeys[string(match[1])] = struct{}{}
	}

	var missing []string
	for key := range loaderKeys {
		if _, ok := rowKeys[key]; !ok {
			missing = append(missing, key)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Fatalf("configuration.md missing table rows for control-plane env keys:\n%s", strings.Join(missing, "\n"))
	}
}
