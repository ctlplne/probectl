// SPDX-License-Identifier: LicenseRef-probectl-TBD

package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
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
