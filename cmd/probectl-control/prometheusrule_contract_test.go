// SPDX-License-Identifier: LicenseRef-probectl-TBD

package main

import (
	"strings"
	"testing"
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

func TestRunOpsPrometheusRuleMetricsAreRegistered(t *testing.T) {
	builders := readArtifact(t, "cmd/probectl-control/builders.go")
	worm := readArtifact(t, "internal/audit/worm.go")
	for _, want := range []string{
		"probectl_agent_registry_expected",
		"probectl_agent_registry_heartbeat_fresh",
		"probectl_agent_registry_dark_fraction",
		`registerClickHouseBreakerGaugeSet(m, "path", pathCH)`,
		`registerClickHouseBreakerGaugeSet(m, "flow", src)`,
		`prefix+"open"`,
	} {
		if !strings.Contains(builders, want) {
			t.Fatalf("builders.go does not register %s", want)
		}
	}
	for _, want := range []string{
		"probectl_audit_worm_last_success_unix_seconds",
		"probectl_audit_worm_signature_failures_total",
		"probectl_audit_worm_chain_failures_total",
	} {
		if !strings.Contains(worm, want) {
			t.Fatalf("worm.go does not register %s", want)
		}
	}
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
