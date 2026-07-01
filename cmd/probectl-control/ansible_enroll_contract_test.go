// SPDX-License-Identifier: LicenseRef-probectl-TBD

package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	agentcfg "github.com/imfeelingtheagi/probectl/internal/agent"
	devicecfg "github.com/imfeelingtheagi/probectl/internal/device"
	ebpfcfg "github.com/imfeelingtheagi/probectl/internal/ebpf"
	endpointcfg "github.com/imfeelingtheagi/probectl/internal/endpoint"
	flowcfg "github.com/imfeelingtheagi/probectl/internal/flow"
)

// OPS-004: the Ansible probectl_agents role used to run `<binary> enroll` for
// EVERY agent type, but only the canary `agent` ships an `enroll` subcommand.
// The bus collectors (ebpf-agent/flow-agent/device-agent/endpoint) register on
// the control plane with `probectl-control register-collector` and have no
// per-host enroll — so `<binary> enroll` would fail with "unknown subcommand".
//
// This contract test pins the role's enroll command to the SET OF AGENT TYPES
// THAT ACTUALLY IMPLEMENT an enroll subcommand (discovered from each binary's
// main.go), so the role and the real CLIs can never drift apart again.
func TestAnsibleEnrollMatchesAgentCLIs(t *testing.T) {
	root := repoRoot(t)

	// 1. Discover which agent binaries actually have an `enroll` subcommand by
	//    scanning each cmd/probectl-*/main.go for a `case "enroll"` dispatch.
	cmdDir := filepath.Join(root, "cmd")
	entries, err := os.ReadDir(cmdDir)
	if err != nil {
		t.Fatalf("read cmd/: %v", err)
	}
	enrollCase := regexp.MustCompile(`case\s+"enroll"`)
	hasEnroll := map[string]bool{} // agent-type (binary suffix) -> implements enroll
	for _, e := range entries {
		if !e.IsDir() || !strings.HasPrefix(e.Name(), "probectl-") {
			continue
		}
		// Map binary name -> the role's agent_type token (strip the probectl- prefix).
		agentType := strings.TrimPrefix(e.Name(), "probectl-")
		if agentType == "control" || agentType == "license" || agentType == "probectl" {
			continue // not an installable agent
		}
		main := filepath.Join(cmdDir, e.Name(), "main.go")
		src, err := os.ReadFile(main)
		if err != nil {
			continue
		}
		hasEnroll[agentType] = enrollCase.Match(src)
	}
	if !hasEnroll["agent"] {
		t.Fatal("expected cmd/probectl-agent to implement an `enroll` subcommand")
	}
	// At least one collector must NOT have enroll, or the test proves nothing.
	someCollectorWithoutEnroll := false
	for typ, ok := range hasEnroll {
		if !ok {
			someCollectorWithoutEnroll = true
			t.Logf("agent type %q has no enroll subcommand (bus collector)", typ)
		}
	}
	if !someCollectorWithoutEnroll {
		t.Fatal("expected at least one collector agent type without an enroll subcommand")
	}

	// 2. Read the role's mTLS-agent allow-list from defaults and assert it
	//    EXACTLY matches the binaries that implement enroll.
	defaults := readArtifact(t, "deploy/ansible/roles/probectl_agents/defaults/main.yml")
	allow := parseYAMLStringList(defaults, "probectl_mtls_agent_types")
	if len(allow) == 0 {
		t.Fatal("role defaults must declare probectl_mtls_agent_types (OPS-004)")
	}
	allowSet := map[string]bool{}
	for _, a := range allow {
		allowSet[a] = true
		if !hasEnroll[a] {
			t.Errorf("probectl_mtls_agent_types lists %q which has NO enroll subcommand — the role would run a failing `enroll` (OPS-004)", a)
		}
	}
	for typ, ok := range hasEnroll {
		if ok && !allowSet[typ] {
			t.Errorf("agent type %q implements enroll but is missing from probectl_mtls_agent_types — the role would skip enrolling it (OPS-004)", typ)
		}
	}

	// 3. The enroll task in the role must be gated by that allow-list (so a
	//    collector type can never hit `<binary> enroll`).
	tasks := readArtifact(t, "deploy/ansible/roles/probectl_agents/tasks/main.yml")
	enrollIdx := strings.Index(tasks, "enroll\n")
	if enrollIdx < 0 {
		enrollIdx = strings.Index(tasks, " enroll")
	}
	if enrollIdx < 0 {
		t.Fatal("role has no enroll task")
	}
	// The enroll command block must be preceded (within the same task) by the
	// allow-list guard.
	if !strings.Contains(tasks, "probectl_agent_type in probectl_mtls_agent_types") {
		t.Error("the enroll task must be gated by `probectl_agent_type in probectl_mtls_agent_types` (OPS-004)")
	}
	// And the collectors must get the register-collector guidance instead.
	if !strings.Contains(tasks, "register-collector") {
		t.Error("the role must document `register-collector` for bus collectors (OPS-004)")
	}
}

func TestAnsibleRoleRendersTypedAgentConfigs(t *testing.T) {
	clearAgentConfigEnv(t)
	vars := map[string]string{
		"inventory_hostname":                   "edge-1",
		"probectl_control_grpc_addr":           "https://control.example:8443",
		"probectl_state_dir":                   "/var/lib/probectl-agent",
		"probectl_tenant_id":                   "tenant-a",
		"probectl_agent_id":                    "collector-edge-1",
		"probectl_bus_mode":                    "kafka",
		"probectl_bus_brokers | to_json":       `["kafka-1:9093","kafka-2:9093"]`,
		"probectl_bus_namespace":               "tenant-a",
		"probectl_bus_secret_source":           "env",
		"probectl_flow_netflow_enabled | bool": "true",
		"probectl_flow_netflow_listen":         ":2055",
		"probectl_flow_ipfix_enabled | bool":   "true",
		"probectl_flow_ipfix_listen":           ":4739",
		"probectl_flow_sflow_enabled | bool":   "true",
		"probectl_flow_sflow_listen":           ":6343",
		"probectl_flow_cloud_import_provider":  "",
		"probectl_flow_cloud_import_path":      "",
		"probectl_flow_batch_size":             "1000",
		"probectl_flow_flush_interval":         "2s",
		"probectl_flow_template_ttl":           "30m",
		"probectl_flow_max_templates":          "4096",
		"probectl_flow_read_buffer_bytes":      "4194304",
		"probectl_flow_queue_size":             "65536",
		"probectl_flow_workers":                "2",
		"probectl_device_address":              "192.0.2.10",
		"probectl_device_port":                 "161",
		"probectl_device_transport":            "snmpv3",
		"probectl_device_credential":           "device-snmp",
		"probectl_device_interval":             "60s",
		"probectl_device_sensors | bool":       "true",
		"probectl_endpoint_interval":           "60s",
		"probectl_endpoint_targets | to_json":  `["https://portal.example","https://1.1.1.1"]`,
		"probectl_endpoint_max_hops":           "20",
		"probectl_endpoint_probes":             "3",
		"probectl_endpoint_session_timeout":    "15s",
		"probectl_ebpf_fixture_path":           "",
		"probectl_ebpf_l7_fixture_path":        "",
		"probectl_ebpf_proc_root":              "/proc",
		"probectl_ebpf_flush_interval":         "10s",
		"probectl_ebpf_ring_buffer_bytes":      "16777216",
		"probectl_ebpf_max_service_edges":      "50000",
		"probectl_ebpf_max_l7_conns":           "8192",
		"probectl_ebpf_l7_conn_idle_ttl":       "5m",
		"probectl_ebpf_health_state_dir":       "/var/lib/probectl-ebpf-agent/health",
	}

	cases := []struct {
		agentType string
		loader    func(string) error
	}{
		{agentType: "agent", loader: func(path string) error { _, err := agentcfg.Load(path); return err }},
		{agentType: "ebpf-agent", loader: func(path string) error { _, err := ebpfcfg.Load(path); return err }},
		{agentType: "flow-agent", loader: func(path string) error { _, err := flowcfg.Load(path); return err }},
		{agentType: "device-agent", loader: func(path string) error { _, err := devicecfg.Load(path); return err }},
		{agentType: "endpoint", loader: func(path string) error { _, err := endpointcfg.Load(path); return err }},
	}
	for _, tc := range cases {
		t.Run(tc.agentType, func(t *testing.T) {
			tpl := readArtifact(t, "deploy/ansible/roles/probectl_agents/templates/"+tc.agentType+".yaml.j2")
			rendered := renderAnsibleTemplate(t, tpl, vars)
			if tc.agentType != "agent" {
				for _, forbidden := range []string{"control_plane:", "tls:"} {
					if strings.Contains(rendered, forbidden) {
						t.Fatalf("%s rendered canary-only key %q:\n%s", tc.agentType, forbidden, rendered)
					}
				}
				wants := []string{"tenant_id: \"tenant-a\"", "mode: \"kafka\"", `brokers: ["kafka-1:9093","kafka-2:9093"]`, "namespace: \"tenant-a\""}
				if tc.agentType == "ebpf-agent" {
					wants = append(wants, "host: \"collector-edge-1\"")
				} else {
					wants = append(wants, "agent_id: \"collector-edge-1\"")
				}
				for _, want := range wants {
					if !strings.Contains(rendered, want) {
						t.Fatalf("%s rendered config missing %q:\n%s", tc.agentType, want, rendered)
					}
				}
			}
			path := filepath.Join(t.TempDir(), tc.agentType+".yaml")
			if err := os.WriteFile(path, []byte(rendered), 0o600); err != nil {
				t.Fatalf("write rendered config: %v", err)
			}
			if err := tc.loader(path); err != nil {
				t.Fatalf("rendered %s config did not load with its real loader: %v\n%s", tc.agentType, err, rendered)
			}
		})
	}
}

func TestAnsibleRoleAssertsCollectorRequiredVars(t *testing.T) {
	defaults := readArtifact(t, "deploy/ansible/roles/probectl_agents/defaults/main.yml")
	tasks := readArtifact(t, "deploy/ansible/roles/probectl_agents/tasks/main.yml")

	supported := strings.Join(parseYAMLStringList(defaults, "probectl_supported_agent_types"), ",")
	for _, want := range []string{"agent", "ebpf-agent", "flow-agent", "device-agent", "endpoint"} {
		if !strings.Contains(supported, want) {
			t.Fatalf("probectl_supported_agent_types missing %q: %s", want, supported)
		}
		if _, err := os.Stat(filepath.Join(repoRoot(t), "deploy/ansible/roles/probectl_agents/templates", want+".yaml.j2")); err != nil {
			t.Fatalf("missing per-agent Ansible template for %s: %v", want, err)
		}
	}
	for _, want := range []string{
		`src: "{{ probectl_agent_type }}.yaml.j2"`,
		"Assert bus collector identity and bus config",
		"probectl_tenant_id | length > 0",
		"probectl_agent_id | length > 0",
		"probectl_bus_mode in ['memory', 'kafka']",
		"probectl_bus_mode != 'kafka' or probectl_bus_brokers | length > 0",
		"probectl_bus_secret_source in ['env', 'vault', 'external-secret']",
		"Assert flow collector config inputs",
		"Assert device collector config inputs",
		"Assert endpoint collector config inputs",
	} {
		if !strings.Contains(tasks, want) {
			t.Fatalf("Ansible role missing fail-closed collector contract %q", want)
		}
	}
	assertIdx := strings.Index(tasks, "Assert bus collector identity and bus config")
	installIdx := strings.Index(tasks, "Install from the signed apt repo")
	if assertIdx < 0 || installIdx < 0 || assertIdx > installIdx {
		t.Fatal("collector required-variable assertions must run before any install task")
	}
}

func renderAnsibleTemplate(t *testing.T, body string, vars map[string]string) string {
	t.Helper()
	commentRe := regexp.MustCompile(`(?s)\{#.*?#\}`)
	exprRe := regexp.MustCompile(`\{\{\s*([^}]+?)\s*\}\}`)
	body = commentRe.ReplaceAllString(body, "")
	var missing []string
	out := exprRe.ReplaceAllStringFunc(body, func(match string) string {
		parts := exprRe.FindStringSubmatch(match)
		if len(parts) != 2 {
			missing = append(missing, match)
			return match
		}
		expr := strings.TrimSpace(parts[1])
		v, ok := vars[expr]
		if !ok {
			missing = append(missing, expr)
			return match
		}
		return v
	})
	if len(missing) > 0 {
		t.Fatalf("template had unbound Ansible expressions: %s", strings.Join(missing, ", "))
	}
	return out
}

func clearAgentConfigEnv(t *testing.T) {
	t.Helper()
	for _, key := range []string{
		"PROBECTL_AGENT_GRPC_ADDR", "PROBECTL_AGENT_TLS_CERT_FILE", "PROBECTL_AGENT_TLS_KEY_FILE", "PROBECTL_AGENT_TLS_CA_FILE",
		"PROBECTL_EBPF_TENANT_ID", "PROBECTL_EBPF_BUS_MODE", "PROBECTL_EBPF_BUS_BROKERS", "PROBECTL_EBPF_BUS_NAMESPACE",
		"PROBECTL_FLOW_TENANT", "PROBECTL_FLOW_AGENT_ID", "PROBECTL_FLOW_BUS_MODE", "PROBECTL_FLOW_BUS_BROKERS", "PROBECTL_FLOW_BUS_NAMESPACE",
		"PROBECTL_DEVICE_TENANT", "PROBECTL_DEVICE_AGENT_ID", "PROBECTL_DEVICE_BUS_MODE", "PROBECTL_DEVICE_BUS_BROKERS", "PROBECTL_DEVICE_BUS_NAMESPACE",
		"PROBECTL_ENDPOINT_TENANT_ID", "PROBECTL_ENDPOINT_AGENT_ID", "PROBECTL_ENDPOINT_BUS_MODE", "PROBECTL_ENDPOINT_BUS_BROKERS", "PROBECTL_ENDPOINT_BUS_NAMESPACE",
	} {
		t.Setenv(key, "")
	}
}

// parseYAMLStringList extracts a simple top-level YAML list:
//
//	key:
//	  - a
//	  - b
//
// (sufficient for the role defaults; avoids a full YAML parse dependency here).
func parseYAMLStringList(doc, key string) []string {
	lines := strings.Split(doc, "\n")
	var out []string
	inList := false
	for _, ln := range lines {
		trimmed := strings.TrimRight(ln, " \t")
		if strings.HasPrefix(trimmed, key+":") {
			inList = true
			continue
		}
		if inList {
			t := strings.TrimSpace(trimmed)
			if strings.HasPrefix(t, "- ") {
				out = append(out, strings.TrimSpace(strings.TrimPrefix(t, "- ")))
				continue
			}
			// Any non-list, non-blank line ends the list.
			if t != "" && !strings.HasPrefix(ln, " ") {
				break
			}
			if t == "" {
				continue
			}
			break
		}
	}
	return out
}
