// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package main

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/ctlplne/probectl/internal/config"
	"github.com/ctlplne/probectl/internal/crypto"
)

// The evaluation stack is the documented first hour (docs/getting-started.md:
// `make first-data`, deploy/compose/eval.yml + eval-synthetic.yml). Beta gate
// G4(a) ran it on a Docker daemon with no cached images or volumes and it did
// not get past its first one-shot: the stack had silently drifted from later
// fail-closed changes, because nothing in CI starts it. These tests hold the
// merged compose model (and the script that drives it) to those contracts
// without needing Docker; each test names the finding it pins.

const evalControlImage = "probectl-control-eval:dev"

type evalService struct {
	Image       string         `yaml:"image"`
	Command     []string       `yaml:"command"`
	Entrypoint  []string       `yaml:"entrypoint"`
	Environment map[string]any `yaml:"environment"`
	DependsOn   map[string]any `yaml:"-"`
	RawDepends  any            `yaml:"depends_on"` // a list or a map in Compose
}

// dependsOn normalizes Compose's two depends_on forms to a set.
func (s evalService) dependsOn() map[string]any {
	out := map[string]any{}
	switch d := s.RawDepends.(type) {
	case []any:
		for _, name := range d {
			out[fmt.Sprint(name)] = nil
		}
	case map[string]any:
		for name, cond := range d {
			out[name] = cond
		}
	}
	return out
}

// loadEvalStack merges eval.yml and the eval-synthetic.yml overlay the way
// `docker compose -f eval.yml -f eval-synthetic.yml` does for the keys these
// contracts read: scalars and lists replace, environment and depends_on merge.
func loadEvalStack(t *testing.T) map[string]*evalService {
	t.Helper()
	merged := map[string]*evalService{}
	for _, name := range []string{"eval.yml", "eval-synthetic.yml"} {
		raw, err := os.ReadFile(filepath.Join("..", "..", "deploy", "compose", name))
		if err != nil {
			t.Fatal(err)
		}
		var doc struct {
			Services map[string]evalService `yaml:"services"`
		}
		if err := yaml.Unmarshal(raw, &doc); err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		for svcName, svc := range doc.Services {
			cur, ok := merged[svcName]
			if !ok {
				cur = &evalService{Environment: map[string]any{}, DependsOn: map[string]any{}}
				merged[svcName] = cur
			}
			if svc.Image != "" {
				cur.Image = svc.Image
			}
			if svc.Command != nil {
				cur.Command = svc.Command
			}
			if svc.Entrypoint != nil {
				cur.Entrypoint = svc.Entrypoint
			}
			for k, v := range svc.Environment {
				cur.Environment[k] = v
			}
			for k, v := range svc.dependsOn() {
				cur.DependsOn[k] = v
			}
		}
	}
	if len(merged) < 8 {
		t.Fatalf("parsed only %d eval services; the contract has stopped reading the stack", len(merged))
	}
	return merged
}

var composeDefaultRe = regexp.MustCompile(`\$\{([A-Z0-9_]+):-([^}]*)\}`)

// envOf resolves a service's environment as Compose would, with interp
// standing in for the --env-file `make first-data` passes.
func envOf(svc *evalService, interp map[string]string) map[string]string {
	out := make(map[string]string, len(svc.Environment))
	for k, v := range svc.Environment {
		s, ok := v.(string)
		if !ok && v != nil {
			s = fmt.Sprint(v)
		}
		out[k] = composeDefaultRe.ReplaceAllStringFunc(s, func(m string) string {
			sub := composeDefaultRe.FindStringSubmatch(m)
			if val, ok := interp[sub[1]]; ok && val != "" {
				return val
			}
			return sub[2]
		})
	}
	return out
}

// firstDataEnvFile is what scripts/first_data.sh writes into
// deploy/compose/.env.eval: one random 32-byte envelope key.
func firstDataEnvFile(t *testing.T) map[string]string {
	t.Helper()
	key, err := crypto.Random(32)
	if err != nil {
		t.Fatal(err)
	}
	return map[string]string{"PROBECTL_EVAL_ENVELOPE_KEY": base64.StdEncoding.EncodeToString(key)}
}

// TestEvalStackControlOneShotsLoadConfig (DPR-302): each one-shot that runs
// the control binary's configured path (everything but gen-cert) must load
// the shared configuration, and if it asks for dev auth it must hold the same
// two runtime locks the binary checks (the ack and a loopback bind). Before
// the fix `migrate` exited 1 on "PROBECTL_SESSION_HMAC_KEY is required" and
// the overlay never started.
func TestEvalStackControlOneShotsLoadConfig(t *testing.T) {
	stack := loadEvalStack(t)
	interp := firstDataEnvFile(t)
	checked := 0
	for name, svc := range stack {
		if svc.Image != evalControlImage || len(svc.Command) == 0 || svc.Command[0] == "gen-cert" {
			continue
		}
		checked++
		env := envOf(svc, interp)
		cfg, err := config.Load(func(k string) string { return env[k] })
		if err != nil {
			t.Errorf("eval one-shot %q (%s) cannot load the control-plane config: %v", name, strings.Join(svc.Command, " "), err)
			continue
		}
		if cfg.AuthMode == "dev" {
			if env["PROBECTL_DEV_AUTH_ACK"] != "i-understand" || !loopbackOnly(cfg.HTTPAddr) {
				t.Errorf("eval one-shot %q selects dev auth without the ack and a loopback bind (validateDevAuthMode would refuse it)", name)
			}
		}
	}
	if checked < 3 {
		t.Fatalf("checked only %d control-image one-shots (want migrate, agent-ca init, agent-ca export)", checked)
	}
}

// TestEvalStackServesAsLeastPrivilegeLogin (DPR-303): the eval control plane
// must serve as the probectl_runtime login the pg-appuser one-shot provisions
// (NOSUPERUSER NOBYPASSRLS, member of probectl_app), with the schema applied
// by a privileged migrate one-shot first. Serving as the Postgres superuser
// makes the TEN-01 isolation self-check refuse to start: before the fix the
// eval control plane crash-looped and no eval path produced data.
func TestEvalStackServesAsLeastPrivilegeLogin(t *testing.T) {
	stack := loadEvalStack(t)
	control, pg, appuser := stack["control"], stack["postgres"], stack["pg-appuser"]
	if control == nil || pg == nil {
		t.Fatal("eval stack has no control or postgres service")
	}
	env := envOf(control, nil)
	dsn, err := url.Parse(env["PROBECTL_DATABASE_URL"])
	if err != nil || dsn.User == nil {
		t.Fatalf("control PROBECTL_DATABASE_URL %q does not name a login", env["PROBECTL_DATABASE_URL"])
	}
	superuser := envOf(pg, nil)["POSTGRES_USER"]
	if login := dsn.User.Username(); login == superuser || login != "probectl_runtime" {
		t.Errorf("eval control serves as %q (postgres superuser is %q); want the least-privilege probectl_runtime login (TEN-01)", login, superuser)
	}
	if env["PROBECTL_MIGRATE_ON_BOOT"] == "true" {
		t.Error("eval control migrates on boot as its least-privilege login; migrations need the privileged migrate one-shot")
	}
	if appuser == nil || !strings.Contains(strings.Join(appuser.Entrypoint, " "), "provision-app-login.sql") {
		t.Fatal("eval stack has no pg-appuser one-shot running deploy/compose/provision-app-login.sql")
	}
	if _, ok := control.DependsOn["pg-appuser"]; !ok {
		t.Error("eval control does not wait for pg-appuser, so it can start before its login exists")
	}
	if _, ok := appuser.DependsOn["migrate"]; !ok {
		t.Error("pg-appuser does not wait for migrate, so probectl_app may not exist yet")
	}
	if m := stack["migrate"]; m == nil || m.Image != evalControlImage || len(m.Command) == 0 || m.Command[0] != "migrate" {
		t.Error("eval.yml has no migrate one-shot on the control image")
	}
}

// TestEvalFixtureAgentRunsAsRegisteredCollector (DPR-304): the fixture eBPF
// agent stamps its own agent_id on every flow (RTP-17) and the control plane
// verifies (tenant, agent) against the registry, so the agent must run as the
// identity eval-registry inserts. Before the fix it defaulted to its container
// hostname and every batch was rejected (TENANT-101): an empty sample graph.
func TestEvalFixtureAgentRunsAsRegisteredCollector(t *testing.T) {
	stack := loadEvalStack(t)
	agent, registry := stack["ebpf-agent"], stack["eval-registry"]
	if agent == nil || registry == nil {
		t.Fatal("eval stack has no ebpf-agent or eval-registry service")
	}
	raw, err := os.ReadFile(filepath.Join("..", "..", "deploy", "compose", "eval.yml"))
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?s)INSERT INTO agents.*?VALUES\s*\(\s*'([0-9a-f-]{36})',\s*'([0-9a-f-]{36})'`).FindSubmatch(raw)
	if m == nil {
		t.Fatal("eval-registry no longer inserts a sample collector row")
	}
	registeredAgent, registeredTenant := string(m[1]), string(m[2])
	env := envOf(agent, nil)
	if got := env["PROBECTL_EBPF_AGENT_ID"]; got != registeredAgent {
		t.Errorf("eval ebpf-agent runs as agent %q; eval-registry registers %q, so every fixture batch is rejected", got, registeredAgent)
	}
	if got := env["PROBECTL_EBPF_TENANT_ID"]; got != registeredTenant {
		t.Errorf("eval ebpf-agent claims tenant %q; eval-registry registers its collector under %q", got, registeredTenant)
	}
}
