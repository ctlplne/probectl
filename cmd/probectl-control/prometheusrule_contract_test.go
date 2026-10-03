// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package main

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var (
	// metricRegistrationPattern matches a registration of a literal probectl_
	// series on a metrics registry — the seam through which a series becomes
	// part of what /metrics exposes. A name that appears only in a comment or an
	// unregistered constant is NOT exported and never matches.
	metricRegistrationPattern = regexp.MustCompile(`\.(?:Gauge|Counter|CounterFunc)\(\s*"(probectl_[a-z0-9_]+)"`)
	// ruleNameMatcherPattern drops __name__=~"..." regex families, whose
	// concrete series names are built at runtime and so cannot be asserted by
	// literal name (the dynamically-named ClickHouse breaker and pipeline/otlp
	// dead-letter families).
	ruleNameMatcherPattern = regexp.MustCompile(`__name__\s*=~\s*"[^"]*"`)
	ruleSeriesPattern      = regexp.MustCompile(`probectl_[a-z0-9_]+`)
)

func TestPrometheusRuleCoversRunOpsCriticalFailureModes(t *testing.T) {
	template := readArtifact(t, "deploy/helm/probectl/templates/prometheusrule.yaml")
	values := readArtifact(t, "deploy/helm/probectl/values.yaml")
	schema := readArtifact(t, "deploy/helm/probectl/values.schema.json")
	runbook := readArtifact(t, "docs/runbooks/probectl-self-alerts.md")
	hardening := readArtifact(t, "scripts/check_helm_hardening.sh")
	promtool := readArtifact(t, "deploy/helm/probectl/tests/prometheusrule-runops.promtool.yaml")

	cases := []struct {
		alert      string
		anchor     string
		thresholds []string
		metrics    []string
	}{
		{
			alert:      "ProbectlDLQGrowth",
			anchor:     "probectldlqgrowth",
			thresholds: []string{"dlqGrowthWindow", "dlqGrowthEvents", "dlqGrowthFor"},
			metrics:    []string{"dead_lettered_total"},
		},
		{
			alert:      "ProbectlBusShedOrHandlerErrors",
			anchor:     "probectlbusshedorhandlererrors",
			thresholds: []string{"busErrorWindow", "busErrorEvents", "busErrorFor"},
			metrics:    []string{"probectl_bus_shed", "probectl_bus_handler_errors", "probectl_bus_memory_dropped"},
		},
		{
			alert:      "ProbectlClickHouseWriteOrBreakerFailures",
			anchor:     "probectlclickhousewriteorbreakerfailures",
			thresholds: []string{"clickhouseFailureWindow", "clickhouseFailureEvents", "clickhouseFailureFor"},
			metrics:    []string{"insert_errors_total", "probectl_clickhouse_.*_breaker_open", "short_circuits"},
		},
		{
			alert:      "ProbectlAgentDarkFleet",
			anchor:     "probectlagentdarkfleet",
			thresholds: []string{"agentDarkFleetFraction", "agentDarkFleetFor"},
			metrics:    []string{"probectl_agent_registry_expected", "probectl_agent_registry_dark_fraction"},
		},
		{
			alert:      "ProbectlFairnessShedOrRejected",
			anchor:     "probectlfairnessshedorrejected",
			thresholds: []string{"fairnessWindow", "fairnessEvents", "fairnessFor"},
			metrics:    []string{"probectl_fairness_shed_units_total", "probectl_fairness_queries_rejected_total"},
		},
		{
			alert:      "ProbectlWORMExportGap",
			anchor:     "probectlwormexportgap",
			thresholds: []string{"wormExportGapSeconds", "wormExportGapFor"},
			metrics:    []string{"probectl_audit_worm_last_success_unix_seconds"},
		},
		{
			alert:      "ProbectlWORMSignatureFailures",
			anchor:     "probectlwormsignaturefailures",
			thresholds: []string{"wormVerifyFailureWindow", "wormVerifyFailures", "wormVerifyFailureFor"},
			metrics:    []string{"probectl_audit_worm_signature_failures_total", "probectl_audit_worm_chain_failures_total"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.alert, func(t *testing.T) {
			for name, body := range map[string]string{
				"template":       template,
				"runbook":        runbook,
				"hardening gate": hardening,
				"promtool tests": promtool,
			} {
				if !strings.Contains(body, tc.alert) {
					t.Fatalf("%s missing %s", name, tc.alert)
				}
			}
			block := alertBlock(template, tc.alert)
			if !strings.Contains(block, "#"+tc.anchor) {
				t.Fatalf("%s runbook_url is not anchored to #%s:\n%s", tc.alert, tc.anchor, block)
			}
			if !strings.Contains(runbook, "### "+tc.alert) {
				t.Fatalf("runbook missing section heading for %s", tc.alert)
			}
			for _, threshold := range tc.thresholds {
				if !strings.Contains(values, threshold+":") {
					t.Errorf("values.yaml missing threshold %s for %s", threshold, tc.alert)
				}
				if !strings.Contains(schema, `"`+threshold+`"`) {
					t.Errorf("values.schema.json missing threshold %s for %s", threshold, tc.alert)
				}
			}
			for _, metric := range tc.metrics {
				if !strings.Contains(block, metric) {
					t.Errorf("template alert %s missing metric fragment %q", tc.alert, metric)
				}
			}
			if !strings.Contains(alertBlock(promtool, tc.alert), "exp_alerts: []") {
				t.Errorf("promtool fixture for %s must include a clear condition", tc.alert)
			}
		})
	}
}

// TestRunOpsPrometheusRuleMetricsAreRegistered is the PLAT-11 strengthening of
// the old check, which merely asserted each metric NAME appeared as a substring
// somewhere in builders.go / worm.go — a comment, or a constant that was defined
// but never registered, satisfied it, so a rule could reference a series the
// /metrics endpoint never exposes and still pass. This gate instead extracts the
// literal probectl_ series each RunOps alert references and requires every one to
// be an actually-registered (exported) series, dovetailing with the exposed-set
// the RTO-08 gate asserts. A ServiceMonitor scrape can only fire an alert whose
// series exist, so an unexported reference must fail here.
func TestRunOpsPrometheusRuleMetricsAreRegistered(t *testing.T) {
	root := repoRoot(t)
	template := readArtifact(t, "deploy/helm/probectl/templates/prometheusrule.yaml")
	registered := registeredProbectlSeries(t, root)

	// The RunOps critical-failure alerts (TestPrometheusRuleCoversRunOpsCriticalFailureModes).
	runOpsAlerts := []string{
		"ProbectlDLQGrowth",
		"ProbectlBusShedOrHandlerErrors",
		"ProbectlClickHouseWriteOrBreakerFailures",
		"ProbectlAgentDarkFleet",
		"ProbectlFairnessShedOrRejected",
		"ProbectlWORMExportGap",
		"ProbectlWORMSignatureFailures",
	}
	checked := 0
	for _, alert := range runOpsAlerts {
		for _, series := range ruleLiteralSeries(alertBlock(template, alert)) {
			checked++
			if !registered[series] {
				t.Errorf("alert %s references %s, which the control plane never registers on /metrics — a ServiceMonitor scrape can never fire it (PLAT-11)", alert, series)
			}
		}
	}
	if checked == 0 {
		t.Fatal("extracted zero literal probectl_ series from the RunOps alerts — the gate would be vacuous")
	}

	// The ClickHouse breaker gauge set is matched by the rule through a
	// __name__=~ family (dropped above because its concrete names are built at
	// runtime), so assert its registration wiring by its helper call sites
	// rather than by literal series name.
	builders := readArtifact(t, "cmd/probectl-control/builders.go")
	for _, want := range []string{
		`registerClickHouseBreakerGaugeSet(m, "path", pathCH)`,
		`registerClickHouseBreakerGaugeSet(m, "flow", src)`,
		`prefix+"open"`,
	} {
		if !strings.Contains(builders, want) {
			t.Errorf("builders.go does not wire the ClickHouse breaker gauge set: missing %q", want)
		}
	}
}

// TestRunOpsPrometheusRuleMetricsRegistrationGateIsNonVacuous proves the gate
// above actually fails on a rule that references an unexported metric, and that
// the extractor does not mistake the probectl_component label key for a series.
func TestRunOpsPrometheusRuleMetricsRegistrationGateIsNonVacuous(t *testing.T) {
	root := repoRoot(t)
	registered := registeredProbectlSeries(t, root)

	const bogus = "probectl_plat11_planted_unexported_series"
	if registered[bogus] {
		t.Fatalf("planted series %q is unexpectedly registered; the gate would be vacuous", bogus)
	}

	// A planted alert that references an unexported series.
	block := "        - alert: Planted\n" +
		"          expr: max(" + bogus + ") > 0\n" +
		"          labels:\n" +
		"            probectl_component: control-plane\n"
	series := ruleLiteralSeries(block)

	var sawBogus bool
	for _, s := range series {
		if s == bogus {
			sawBogus = true
		}
		if s == "probectl_component" {
			t.Fatal("extractor must not treat the label key probectl_component as a series")
		}
	}
	if !sawBogus {
		t.Fatalf("extractor failed to pick up the planted series %q from %v", bogus, series)
	}

	// Mirror the live gate against the planted rule: the unexported series must
	// be the one — and only — series it reports missing.
	var missing []string
	for _, s := range series {
		if !registered[s] {
			missing = append(missing, s)
		}
	}
	if len(missing) != 1 || missing[0] != bogus {
		t.Fatalf("gate did not isolate the planted unexported series; missing=%v", missing)
	}
}

// registeredProbectlSeries returns every literal probectl_ series registered on
// a metrics registry anywhere in the shipped (non-test) Go tree — the set a
// /metrics scrape can expose.
func registeredProbectlSeries(t *testing.T, root string) map[string]bool {
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
		for _, m := range metricRegistrationPattern.FindAllStringSubmatch(string(b), -1) {
			found[m[1]] = true
		}
		return nil
	})
	if err != nil {
		t.Fatalf("scan repo for metric registrations: %v", err)
	}
	return found
}

// ruleLiteralSeries returns the distinct literal probectl_ series a PromQL rule
// body references, dropping __name__=~"..." regex families and YAML label keys
// (a probectl_ token immediately followed by ':', e.g. probectl_component:).
func ruleLiteralSeries(ruleText string) []string {
	cleaned := ruleNameMatcherPattern.ReplaceAllString(ruleText, "")
	seen := map[string]bool{}
	var out []string
	for _, loc := range ruleSeriesPattern.FindAllStringIndex(cleaned, -1) {
		if loc[1] < len(cleaned) && cleaned[loc[1]] == ':' {
			continue
		}
		name := cleaned[loc[0]:loc[1]]
		if !seen[name] {
			seen[name] = true
			out = append(out, name)
		}
	}
	return out
}

func alertBlock(body, alert string) string {
	start := strings.Index(body, alert)
	if start < 0 {
		return ""
	}
	rest := body[start:]
	next := strings.Index(rest[len(alert):], "alert:")
	if next < 0 {
		return rest
	}
	return rest[:len(alert)+next]
}
