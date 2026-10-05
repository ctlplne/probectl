// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package main

import (
	"os/exec"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func renderHelmBrowserAgent(t *testing.T, extra ...string) (string, error) {
	t.Helper()
	args := []string{
		"template", "probectl", "deploy/helm/probectl",
		"--namespace", "probectl",
		"--show-only", "templates/browser-agent.yaml",
		"--set", "browserAgent.enabled=true",
		"--set", "browserAgent.image.digest=sha256:0000000000000000000000000000000000000000000000000000000000000000",
		"--set", "browserAgent.configSecret=probectl-browser-agent-config",
		"--set-json", `browserAgent.networkPolicy.egressTo=[{"to":[{"ipBlock":{"cidr":"0.0.0.0/0"}}],"ports":[{"protocol":"TCP","port":443}]}]`,
		"--set", "control.trustedProxies={10.244.0.0/16}",
		"--set", "ingress.host=h.example.com",
		"--set", "ingress.tlsSecretName=probectl-tls",
		"--set", "ingress.backendTLS.trustSecret=probectl-backend-ca",
		"--set", "ingress.backendTLS.serverName=probectl-control.probectl.svc",
		"--set", "control.tls.existingSecret=probectl-control-tls",
		"--set", "image.digest=sha256:0000000000000000000000000000000000000000000000000000000000000000",
		"--set", "secrets.envelopeKey=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		"--set-string", "secrets.sessionHMACKey=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
		"--set", "database.url=postgres://probectl:render-test@db:5432/probectl?sslmode=require",
	}
	args = append(args, extra...)
	cmd := exec.Command("helm", args...)
	cmd.Dir = repoRoot(t)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

type baEnv struct {
	Name  string `yaml:"name"`
	Value string `yaml:"value"`
}

type baMount struct {
	Name      string `yaml:"name"`
	MountPath string `yaml:"mountPath"`
}

type baSecurityContext struct {
	RunAsNonRoot             *bool `yaml:"runAsNonRoot"`
	AllowPrivilegeEscalation *bool `yaml:"allowPrivilegeEscalation"`
	ReadOnlyRootFilesystem   *bool `yaml:"readOnlyRootFilesystem"`
	Privileged               *bool `yaml:"privileged"`
	Capabilities             struct {
		Drop []string `yaml:"drop"`
	} `yaml:"capabilities"`
}

type baContainer struct {
	Name            string            `yaml:"name"`
	Command         []string          `yaml:"command"`
	Env             []baEnv           `yaml:"env"`
	SecurityContext baSecurityContext `yaml:"securityContext"`
	VolumeMounts    []baMount         `yaml:"volumeMounts"`
}

func (c baContainer) env(key string) (string, bool) {
	for _, e := range c.Env {
		if e.Name == key {
			return e.Value, true
		}
	}
	return "", false
}

func (c baContainer) mounts(vol string) bool {
	for _, m := range c.VolumeMounts {
		if m.Name == vol {
			return true
		}
	}
	return false
}

type browserAgentDaemonSet struct {
	Spec struct {
		Template struct {
			Spec struct {
				Containers []baContainer `yaml:"containers"`
			} `yaml:"spec"`
		} `yaml:"template"`
	} `yaml:"spec"`
}

func (ds browserAgentDaemonSet) container(name string) (baContainer, bool) {
	for _, c := range ds.Spec.Template.Spec.Containers {
		if c.Name == name {
			return c, true
		}
	}
	return baContainer{}, false
}

func parseBrowserAgent(t *testing.T) browserAgentDaemonSet {
	t.Helper()
	out, err := renderHelmBrowserAgent(t)
	if err != nil {
		t.Fatalf("render browser-agent.yaml: %v\n%s", err, out)
	}
	var ds browserAgentDaemonSet
	if err := yaml.Unmarshal([]byte(out), &ds); err != nil {
		t.Fatalf("parse rendered DaemonSet: %v\n%s", err, out)
	}
	// seccomp is a pod-level field this gate checks by substring (it is not on
	// the per-container struct above).
	if !strings.Contains(out, "seccompProfile:") || !strings.Contains(out, "RuntimeDefault") {
		t.Errorf("SUP-02: the browser-agent pod must set seccompProfile RuntimeDefault:\n%s", out)
	}
	return ds
}

// TestBrowserAgentContainerIsHardened closes SUP-02. The browser-agent runs
// headless Chromium over UNTRUSTED web content with Chromium's own sandbox
// necessarily disabled (the pod forbids the privileges it needs — see
// worker.mjs), so every container's securityContext is the isolation boundary
// and must stay maximally locked down. Both the agent and the Chromium worker
// are asserted, so neither can silently regress.
//
// Fail-before (non-vacuity): weaken any one of these on either container (allow
// privilege escalation, add a capability, drop readOnlyRootFilesystem) and the
// matching assertion fires.
func TestBrowserAgentContainerIsHardened(t *testing.T) {
	requireOrSkipHelm(t)
	ds := parseBrowserAgent(t)
	for _, name := range []string{"browser-agent", "browser-worker"} {
		c, ok := ds.container(name)
		if !ok {
			t.Fatalf("SUP-02: rendered pod has no %q container (the agent↔worker split must produce both)", name)
		}
		sc := c.SecurityContext
		if sc.RunAsNonRoot == nil || !*sc.RunAsNonRoot {
			t.Errorf("SUP-02: %s container must runAsNonRoot", name)
		}
		if sc.AllowPrivilegeEscalation == nil || *sc.AllowPrivilegeEscalation {
			t.Errorf("SUP-02: %s container must set allowPrivilegeEscalation: false", name)
		}
		if sc.ReadOnlyRootFilesystem == nil || !*sc.ReadOnlyRootFilesystem {
			t.Errorf("SUP-02: %s container must set readOnlyRootFilesystem: true", name)
		}
		if sc.Privileged != nil && *sc.Privileged {
			t.Errorf("SUP-02: %s container must never be privileged", name)
		}
		dropsAll := false
		for _, d := range sc.Capabilities.Drop {
			if d == "ALL" {
				dropsAll = true
			}
		}
		if !dropsAll {
			t.Errorf("SUP-02: %s container must drop ALL capabilities (got %v)", name, sc.Capabilities.Drop)
		}
	}
}

// TestBrowserAgentSidecarKeepsSVIDOutOfRenderer closes the ARCHITECTURE half of
// SUP-02 (D-36, decided 2026-10-05): the agent's mTLS identity (browser-config:
// cert.pem / key.pem / ca.pem) must be mounted ONLY in the agent container, never
// in the Chromium renderer — otherwise a browser RCE could read the agent key and
// impersonate the tenant's agent. The renderer is a SEPARATE sidecar driven over
// a shared UNIX socket.
//
// Fail-before: the pre-split single-container template mounted browser-config in
// the one container that also ran Chromium, so there was no renderer container
// WITHOUT the SVID and this gate's "browser-worker has no browser-config mount"
// assertion could not hold.
func TestBrowserAgentSidecarKeepsSVIDOutOfRenderer(t *testing.T) {
	requireOrSkipHelm(t)
	ds := parseBrowserAgent(t)

	agent, ok := ds.container("browser-agent")
	if !ok {
		t.Fatal("no browser-agent container")
	}
	worker, ok := ds.container("browser-worker")
	if !ok {
		t.Fatal("no browser-worker container")
	}

	// The SVID secret is mounted in the agent, and NOT in the renderer.
	if !agent.mounts("browser-config") {
		t.Errorf("SUP-02/D-36: the agent container must mount the browser-config SVID secret: %+v", agent.VolumeMounts)
	}
	if worker.mounts("browser-config") {
		t.Errorf("SUP-02/D-36: the Chromium renderer must NOT mount browser-config (the agent SVID) — a browser RCE could exfiltrate key.pem: %+v", worker.VolumeMounts)
	}
	// Both must share the IPC socket volume so the agent can drive the worker.
	if !agent.mounts("browser-worker-ipc") || !worker.mounts("browser-worker-ipc") {
		t.Error("SUP-02/D-36: agent and worker must share the browser-worker-ipc socket volume")
	}

	// The agent drives the worker over the socket, not a local child process.
	if v, ok := agent.env("PROBECTL_AGENT_BROWSER_WORKER_SOCKET"); !ok || v == "" {
		t.Error("SUP-02/D-36: the agent must set PROBECTL_AGENT_BROWSER_WORKER_SOCKET so it drives the sidecar over the socket")
	}
	if v, ok := agent.env("PROBECTL_AGENT_BROWSER_WORKER_COMMAND"); !ok || v != "" {
		t.Errorf("SUP-02/D-36: the agent must clear PROBECTL_AGENT_BROWSER_WORKER_COMMAND so it cannot spawn a renderer in the identity-bearing container (got %q, present=%v)", v, ok)
	}

	// The worker runs the Playwright worker in socket-server mode.
	if len(worker.Command) == 0 || worker.Command[0] != "node" {
		t.Errorf("SUP-02/D-36: the worker container must run `node /worker/worker.mjs` (got command %v)", worker.Command)
	}
	if v, ok := worker.env("PROBECTL_BROWSER_WORKER_SOCKET"); !ok || v == "" {
		t.Error("SUP-02/D-36: the worker must set PROBECTL_BROWSER_WORKER_SOCKET to listen for the agent")
	}
}
