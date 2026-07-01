// SPDX-License-Identifier: LicenseRef-probectl-TBD

package cli

import (
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
)

type requiredFeature struct {
	ID     string
	Name   string
	Status string
}

type cliFeatureCoverage struct {
	Command string
	Reason  string
}

var requiredFeatureCLICoverage = map[string]cliFeatureCoverage{
	"PLANE_ACTIVE_SYNTHETIC": {Command: "probectl test list"},
	"PLANE_BGP_ROUTING":      {Command: "probectl bgp events"},
	"PLANE_FLOW_ANALYTICS":   {Command: "probectl flow top"},
	"PLANE_DEVICE_TELEMETRY": {Command: "probectl device list"},
	"PLANE_EBPF_HOST_L7":     {Command: "probectl ebpf service-map"},
	"F1":                     {Command: "probectl agent list"},
	"F2":                     {Command: "probectl test create"},
	"F3":                     {Command: "probectl test path"},
	"F4":                     {Command: "probectl test create"},
	"F5":                     {Command: "probectl test create"},
	"F6":                     {Command: "probectl bgp events"},
	"F7":                     {Command: "probectl outage list"},
	"F8":                     {Command: "probectl alert list"},
	"F9":                     {Command: "probectl incident list"},
	"F10":                    {Command: "probectl api GET /openapi.json"},
	"F11":                    {Command: "probectl ebpf service-map"},
	"F12":                    {Command: "probectl otlp traces"},
	"F13":                    {Command: "probectl ai ask"},
	"F14":                    {Reason: "MCP is a separate JSON-RPC/server transport; no probectl CLI subcommand is intended because operators use MCP clients."},
	"F15":                    {Command: "probectl test create"},
	"F16":                    {Command: "probectl endpoint list"},
	"F17":                    {Command: "probectl flow top"},
	"F18":                    {Command: "probectl device metrics"},
	"F19":                    {Command: "probectl outage list"},
	"F20":                    {Command: "probectl rum summary"},
	"F21":                    {Command: "probectl test create"},
	"F22":                    {Command: "probectl me show"},
	"F23":                    {Command: "probectl audit list"},
	"F24":                    {Command: "probectl hierarchy show"},
	"F25":                    {Command: "probectl scim tokens"},
	"F26":                    {Command: "probectl siem status"},
	"F27":                    {Command: "probectl oncall alerts"},
	"F28":                    {Command: "probectl rollout list"},
	"F29":                    {Reason: "IaC and GitOps are external Terraform/Helm/GitOps workflows; probectl does not wrap those tools."},
	"F30":                    {Command: "probectl cmdb lookup"},
	"F31":                    {Command: "probectl secret health"},
	"F32":                    {Command: "probectl editions status"},
	"F33":                    {Reason: "Multi-region and HA are deployment/runbook concerns; no tenant-scoped CLI operation is promised."},
	"F34":                    {Command: "probectl governance tenant"},
	"F35":                    {Command: "probectl diagnostics bundle"},
	"F36":                    {Command: "probectl tls posture"},
	"F37":                    {Command: "probectl threat detections"},
	"F38":                    {Command: "probectl threat detections"},
	"F39":                    {Command: "probectl change list"},
	"F40":                    {Command: "probectl topology show"},
	"F41":                    {Command: "probectl cost summary"},
	"F42":                    {Command: "probectl slo list"},
	"F43":                    {Command: "probectl compliance summary"},
	"F44":                    {Command: "probectl remediation list"},
	"F45":                    {Command: "probectl ai author"},
	"F46":                    {Command: "probectl endpoint list"},
	"F47":                    {Reason: "Network chaos uses the dedicated probectl-chaos-dependency-drill/test harness, not a control-plane API namespace."},
	"F48":                    {Command: "probectl carbon summary"},
	"F49":                    {Reason: "Future Phase-4 marketplace feature; no current GA CLI surface is promised."},
	"F50":                    {Command: "probectl tenant list"},
	"F51":                    {Command: "probectl provider tenants"},
	"F52":                    {Command: "probectl isolation tenants"},
	"F53":                    {Command: "probectl billing usage"},
	"F54":                    {Command: "probectl branding provider"},
	"F55":                    {Command: "probectl lifecycle export"},
	"F56":                    {Command: "probectl key list"},
	"F57":                    {Command: "probectl fairness status"},
}

func TestCLIRequiredFeatureDenominator(t *testing.T) {
	features := parseRequiredFeatures(t)
	if len(features) != 62 {
		t.Fatalf("REQUIRED_FEATURES count = %d, want 62", len(features))
	}
	seen := map[string]bool{}
	var violations []string
	for _, f := range features {
		seen[f.ID] = true
		cov, ok := requiredFeatureCLICoverage[f.ID]
		if !ok {
			violations = append(violations, f.ID+" "+f.Name+": missing CLI coverage entry")
			continue
		}
		switch {
		case cov.Command != "":
			if !cliCommandExists(cov.Command) {
				violations = append(violations, f.ID+" "+f.Name+": command does not resolve: "+cov.Command)
			}
		case cov.Reason != "":
			if f.Status != "future" && !strings.Contains(strings.ToLower(cov.Reason), "no") {
				violations = append(violations, f.ID+" "+f.Name+": exception must explain why no CLI is intended")
			}
		default:
			violations = append(violations, f.ID+" "+f.Name+": empty CLI coverage entry")
		}
	}
	for id := range requiredFeatureCLICoverage {
		if !seen[id] {
			violations = append(violations, id+": CLI coverage references unknown REQUIRED_FEATURES id")
		}
	}
	sort.Strings(violations)
	if len(violations) > 0 {
		t.Fatalf("CLI feature denominator violations:\n%s", strings.Join(violations, "\n"))
	}
}

func parseRequiredFeatures(t *testing.T) []requiredFeature {
	t.Helper()
	raw, err := os.ReadFile("../../web/src/featureCatalog.ts")
	if err != nil {
		t.Fatal(err)
	}
	re := regexp.MustCompile(`(?s)\{\s*id: '([^']+)'.*?name: '([^']+)'.*?status: '([^']+)'`)
	matches := re.FindAllStringSubmatch(string(raw), -1)
	out := make([]requiredFeature, 0, len(matches))
	for _, m := range matches {
		out = append(out, requiredFeature{ID: m[1], Name: m[2], Status: m[3]})
	}
	return out
}

func cliCommandExists(command string) bool {
	parts := strings.Fields(command)
	if len(parts) < 2 || parts[0] != "probectl" {
		return false
	}
	switch parts[1] {
	case "api", "test", "agent", "lifecycle", "version":
		return true
	}
	spec, ok := surfaceCommands[parts[1]]
	if !ok || len(parts) < 3 {
		return false
	}
	_, ok = spec.Ops[parts[2]]
	return ok
}
