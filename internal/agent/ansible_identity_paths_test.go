// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package agent

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

// TestAnsibleAgentConfigUsesRealIdentityFilenames closes SUP-08: the Ansible
// role's agent.yaml.j2 points the agent's mTLS config at the identity files the
// agent ACTUALLY writes at enrollment. It used agent.crt/agent.key/ca.crt —
// names the agent never creates — so a host provisioned by the role rendered a
// config referencing non-existent files and could not load its identity or
// verify the control plane. This binds the template to the Go constants, so a
// future rename of one without the other fails here.
//
// Fail-before: with agent.crt/agent.key/ca.crt in the template, each basename
// mismatches its constant and the assertions fire.
func TestAnsibleAgentConfigUsesRealIdentityFilenames(t *testing.T) {
	root := repoRootForTest(t)
	tmpl, err := os.ReadFile(filepath.Join(root, "deploy", "ansible", "roles", "probectl_agents", "templates", "agent.yaml.j2"))
	if err != nil {
		t.Fatalf("read agent.yaml.j2: %v", err)
	}
	body := string(tmpl)

	field := func(key string) string {
		m := regexp.MustCompile(key + `:\s*"[^"]*/([^/"]+)"`).FindStringSubmatch(body)
		if m == nil {
			t.Fatalf("SUP-08: agent.yaml.j2 has no tls.%s path", key)
		}
		return m[1]
	}
	for _, c := range []struct {
		key, got, want string
	}{
		{"cert_file", field("cert_file"), IdentityCertFile},
		{"key_file", field("key_file"), IdentityKeyFile},
		// The agent verifies the CONTROL PLANE with the server-CA bundle.
		{"ca_file", field("ca_file"), IdentityServerCAFile},
	} {
		if c.got != c.want {
			t.Errorf("SUP-08: agent.yaml.j2 tls.%s uses %q but the agent writes %q (internal/agent/identity.go)", c.key, c.got, c.want)
		}
	}

	// RTO-23: the enroll IDEMPOTENCY probe in tasks/main.yml must stat the file
	// enroll actually writes (IdentityCertFile), or the role re-enrolls on every
	// run (never idempotent). It used identity/agent.crt — a file never created.
	tasks, err := os.ReadFile(filepath.Join(root, "deploy", "ansible", "roles", "probectl_agents", "tasks", "main.yml"))
	if err != nil {
		t.Fatalf("read tasks/main.yml: %v", err)
	}
	statRe := regexp.MustCompile(`path:\s*"\{\{ probectl_state_dir \}\}/identity/([A-Za-z0-9_.]+)"`)
	m := statRe.FindStringSubmatch(string(tasks))
	if m == nil {
		t.Fatalf("RTO-23: no identity stat path found in tasks/main.yml")
	}
	if m[1] != IdentityCertFile {
		t.Errorf("RTO-23: enroll idempotency stat checks identity/%s but enroll writes %q — the role never becomes idempotent", m[1], IdentityCertFile)
	}
}

func repoRootForTest(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not locate repo root (go.mod)")
		}
		dir = parent
	}
}
