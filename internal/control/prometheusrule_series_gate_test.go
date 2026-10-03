// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/config"
	"github.com/ctlplne/probectl/internal/logging"
)

// RTO-08: the shipped Helm PrometheusRule (deploy/helm/probectl/templates/
// prometheusrule.yaml) alerts on self/cluster/fairness series. Five of those
// alerts referenced series that /metrics never exposed — they existed only as
// per-tenant series remote-written into probectl's own TSDB — so a
// ServiceMonitor scrape of /metrics could never fire them. This gate
// cross-checks that every LITERAL series the rule references is present in the
// control's exposed /metrics registry, so rule↔exposition drift fails CI.
//
// Regex-matcher families ({__name__=~"..."}) are deliberately out of scope:
// they target dynamically-named metric families (clickhouse breaker, otlp/
// pipeline dead-letter) whose concrete names are built at runtime, not literal
// series this gate could assert the presence of by name.

var (
	ruleNameMatcherRe = regexp.MustCompile(`__name__\s*=~\s*"[^"]*"`)
	ruleSeriesRe      = regexp.MustCompile(`probectl_[a-z0-9_]+`)
	// A registry registration of a literal probectl_ series name. The series
	// in the rule that /metrics serves are registered through one of these
	// seams (or emitted directly by the metrics Handler, caught by the live
	// scrape below).
	metricRegistrationRe = regexp.MustCompile(`\.(?:Gauge|Counter|CounterFunc)\(\s*"(probectl_[a-z0-9_]+)"`)
)

// extractReferencedSeries returns the distinct literal probectl_ series names a
// PromQL rule body references, dropping __name__=~"..." regex families and YAML
// label keys (a probectl_ token immediately followed by ':', e.g.
// probectl_component:).
func extractReferencedSeries(ruleText string) []string {
	cleaned := ruleNameMatcherRe.ReplaceAllString(ruleText, "")
	seen := map[string]bool{}
	var out []string
	for _, loc := range ruleSeriesRe.FindAllStringIndex(cleaned, -1) {
		if loc[1] < len(cleaned) && cleaned[loc[1]] == ':' {
			continue // YAML key / label name, not a series reference
		}
		name := cleaned[loc[0]:loc[1]]
		if seen[name] {
			continue
		}
		seen[name] = true
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

func findRepoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("could not locate go.mod walking up from %q", dir)
		}
		dir = parent
	}
}

// scrapeExposedSeries renders /metrics from a real control server and returns
// the probectl_ sample names it carries at construction time (build info,
// runtime/self, audit-retention, and the RTO-08 cluster/fairness series — all
// registered unconditionally in New).
func scrapeExposedSeries(t *testing.T) map[string]bool {
	t.Helper()
	cfg := &config.Config{HTTPAddr: ":0", AuthMode: "session", HSTSEnabled: true, HSTSMaxAge: time.Hour}
	s := New(cfg, logging.New(io.Discard, "error", "json"), nil, nil, nil, nil)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("/metrics returned %d", rec.Code)
	}
	exposed := map[string]bool{}
	for _, line := range strings.Split(rec.Body.String(), "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name := line
		if i := strings.IndexAny(name, " {"); i >= 0 {
			name = name[:i]
		}
		if strings.HasPrefix(name, "probectl_") {
			exposed[name] = true
		}
	}
	return exposed
}

// scanRegisteredSeries finds every literal probectl_ series registered on a
// metrics registry anywhere in the shipped (non-test) Go tree. This covers the
// series registered by background wiring a bare New server does not stand up —
// the bus, agent-registry and audit-WORM counters/gauges.
func scanRegisteredSeries(t *testing.T, root string) map[string]bool {
	t.Helper()
	found := map[string]bool{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", "vendor":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, m := range metricRegistrationRe.FindAllStringSubmatch(string(b), -1) {
			found[m[1]] = true
		}
		return nil
	})
	if err != nil {
		t.Fatalf("scan repo for metric registrations: %v", err)
	}
	return found
}

func exposableSeries(t *testing.T, root string) map[string]bool {
	exposable := scrapeExposedSeries(t)
	for name := range scanRegisteredSeries(t, root) {
		exposable[name] = true
	}
	return exposable
}

func TestPrometheusRuleSeriesAreExposedOnMetrics(t *testing.T) {
	root := findRepoRoot(t)
	ruleBytes, err := os.ReadFile(filepath.Join(root, "deploy", "helm", "probectl", "templates", "prometheusrule.yaml"))
	if err != nil {
		t.Fatalf("read PrometheusRule template: %v", err)
	}
	referenced := extractReferencedSeries(string(ruleBytes))
	if len(referenced) == 0 {
		t.Fatal("extracted zero series from the PrometheusRule — the gate would be vacuous")
	}

	exposable := exposableSeries(t, root)

	var missing []string
	for _, name := range referenced {
		if !exposable[name] {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		t.Fatalf("PrometheusRule references %d series the control /metrics registry never exposes "+
			"(a ServiceMonitor scrape can never fire their alerts): %s",
			len(missing), strings.Join(missing, ", "))
	}
}

// TestPrometheusRuleSeriesGateIsNonVacuous keeps the gate above honest: it must
// flag a rule that references a never-exposed series, and must not mistake the
// probectl_component label key for a series.
func TestPrometheusRuleSeriesGateIsNonVacuous(t *testing.T) {
	const bogus = "probectl_rto08_planted_never_exposed"
	ruleText := "        - alert: Planted\n" +
		"          expr: max(" + bogus + ") > 0\n" +
		"          labels:\n" +
		"            probectl_component: control-plane\n"

	referenced := extractReferencedSeries(ruleText)
	var sawBogus bool
	for _, n := range referenced {
		if n == bogus {
			sawBogus = true
		}
		if n == "probectl_component" {
			t.Fatal("extractor must not treat the label key probectl_component as a series")
		}
	}
	if !sawBogus {
		t.Fatalf("extractor failed to pick up the planted series %q", bogus)
	}

	root := findRepoRoot(t)
	exposable := exposableSeries(t, root)
	if exposable[bogus] {
		t.Fatalf("planted series %q unexpectedly in the exposable set", bogus)
	}
	// Mirror the live gate's check against the planted rule: it must report the
	// bogus series as missing, proving the assertion is not vacuous.
	var missing []string
	for _, name := range referenced {
		if !exposable[name] {
			missing = append(missing, name)
		}
	}
	if len(missing) != 1 || missing[0] != bogus {
		t.Fatalf("gate did not isolate the planted series; missing=%v", missing)
	}
}
