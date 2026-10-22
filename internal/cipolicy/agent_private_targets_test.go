// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package cipolicy

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// Beta gate G9, decision of record D-57 (option a): a central test may probe a
// private, loopback or link-local target only when the agent's OWN config sets
// test_sync.allow_private_targets: true (internal/agent/testsync.go; the agent
// default is false and the control plane cannot change it). The shipped agent
// configs of the single-tenant (sovereign) evaluation stack, where the operator
// owns both ends, opt in explicitly and say why in a comment; every other
// shipped agent config (packages, cloud-init, Ansible, the documented example,
// anything an MSP-hosted install deploys) keeps false or leaves the default.
// The planted configs in testdata prove the judge still bites (fail-before).

// agentConfigAPIVersion marks a canary agent config (internal/agent
// ConfigAPIVersion); the eBPF/flow/device agents have their own and no
// test_sync block.
const agentConfigAPIVersion = "apiVersion: probectl.io/agent/v1"

// sovereignAgentConfigs are the only shipped agent configs that may opt in:
// the canaries eval-synthetic.yml runs beside the single-profile eval stack.
var sovereignAgentConfigs = map[string]bool{
	"deploy/compose/eval-agent.yml":         true,
	"deploy/compose/eval-browser-agent.yml": true,
}

// sovereignStackFiles are the compose files that run those canaries; none may
// move the control plane off PROBECTL_DEPLOYMENT_PROFILE=single.
var sovereignStackFiles = []string{"deploy/compose/eval.yml", "deploy/compose/eval-synthetic.yml"}

// sovereignReasonPhrases must appear in the comment directly above the
// opt-in, so the reason travels with the value.
var sovereignReasonPhrases = []string{"single-tenant", "operator owns both ends", "D-57"}

const plantedPrivateTargetsDir = "internal/cipolicy/testdata/agent-private-targets"

// allowPrivateTrueRe finds an uncommented allow_private_targets set to a YAML
// truthy value anywhere in a file (Helm values/templates, Terraform, Ansible).
var allowPrivateTrueRe = regexp.MustCompile(`(?mi)^[^#\n]*\ballow_private_targets["']?\s*[:=]\s*["']?(true|yes|on)\b`)

var deploymentProfileRe = regexp.MustCompile(`(?m)^[^#\n]*PROBECTL_DEPLOYMENT_PROFILE["']?\s*[:=]\s*["']?([A-Za-z0-9_${}:.-]+)`)

// agentPrivateTargetsSetting reports the test_sync.allow_private_targets
// value ("" when the key is absent) and the comment directly above the key.
func agentPrivateTargetsSetting(text string) (value, comment string, err error) {
	var doc yaml.Node
	if err := yaml.Unmarshal([]byte(text), &doc); err != nil {
		return "", "", err
	}
	if len(doc.Content) == 0 {
		return "", "", nil
	}
	sync := mappingValue(doc.Content[0], "test_sync")
	if sync == nil {
		return "", "", nil
	}
	for i := 0; i+1 < len(sync.Content); i += 2 {
		if sync.Content[i].Value == "allow_private_targets" {
			return sync.Content[i+1].Value, sync.Content[i].HeadComment, nil
		}
	}
	return "", "", nil
}

func mappingValue(n *yaml.Node, key string) *yaml.Node {
	if n == nil || n.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			return n.Content[i+1]
		}
	}
	return nil
}

// judgeAgentPrivateTargets returns the D-57 violations of one canary agent
// config. sovereign configs must opt in with the reason above the value; all
// others must leave the default or say false.
func judgeAgentPrivateTargets(name, text string, sovereign bool) []string {
	value, comment, err := agentPrivateTargetsSetting(text)
	if err != nil {
		return []string{name + ": does not parse as YAML: " + err.Error()}
	}
	if !sovereign {
		if value != "" && value != "false" {
			return []string{name + ": test_sync.allow_private_targets = " + value +
				"; only the single-tenant (sovereign) agent configs may opt in, every other agent config keeps false (D-57)"}
		}
		return nil
	}
	var out []string
	if value != "true" {
		out = append(out, name+": the single-tenant (sovereign) agent config must set test_sync.allow_private_targets: true explicitly, or onboarding's 127.0.0.1 first test is refused (D-57); got "+quoteOrAbsent(value))
	}
	for _, phrase := range sovereignReasonPhrases {
		if !strings.Contains(strings.ToLower(comment), strings.ToLower(phrase)) {
			out = append(out, name+": the comment directly above test_sync.allow_private_targets must say why it is true (missing "+phrase+")")
		}
	}
	return out
}

func quoteOrAbsent(v string) string {
	if v == "" {
		return "(absent)"
	}
	return v
}

// templateCommentRe strips Jinja comments/statements so an Ansible template
// parses as the YAML it renders.
var templateCommentRe = regexp.MustCompile(`(?s)\{#.*?#\}|\{%.*?%\}`)

// discoveredAgentConfig is one canary agent config found under deploy/.
type discoveredAgentConfig struct {
	name string // repo-relative, with #n for an embedded cloud-init file
	text string
}

// discoverAgentConfigs walks deploy/ for every canary agent config: plain
// YAML, Jinja templates, and configs embedded in cloud-init write_files.
func discoverAgentConfigs(t *testing.T, root string) []discoveredAgentConfig {
	t.Helper()
	var found []discoveredAgentConfig
	err := filepath.WalkDir(filepath.Join(root, "deploy"), func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		name := filepath.ToSlash(strings.TrimPrefix(path, root+string(filepath.Separator)))
		ext := filepath.Ext(path)
		if ext != ".yml" && ext != ".yaml" && ext != ".j2" {
			return nil
		}
		b, rerr := os.ReadFile(path)
		if rerr != nil {
			return rerr
		}
		text := string(b)
		if !strings.Contains(text, agentConfigAPIVersion) {
			return nil
		}
		if strings.HasPrefix(text, "#cloud-config") {
			found = append(found, cloudInitAgentConfigs(t, name, text)...)
			return nil
		}
		if ext == ".j2" {
			text = templateCommentRe.ReplaceAllString(text, "")
		}
		found = append(found, discoveredAgentConfig{name: name, text: text})
		return nil
	})
	if err != nil {
		t.Fatalf("walk deploy/: %v", err)
	}
	sort.Slice(found, func(i, j int) bool { return found[i].name < found[j].name })
	return found
}

func cloudInitAgentConfigs(t *testing.T, name, text string) []discoveredAgentConfig {
	t.Helper()
	var ci struct {
		WriteFiles []struct {
			Path    string `yaml:"path"`
			Content string `yaml:"content"`
		} `yaml:"write_files"`
	}
	if err := yaml.Unmarshal([]byte(text), &ci); err != nil {
		t.Fatalf("%s: cloud-init does not parse: %v", name, err)
	}
	var out []discoveredAgentConfig
	for _, f := range ci.WriteFiles {
		if strings.Contains(f.Content, agentConfigAPIVersion) {
			out = append(out, discoveredAgentConfig{name: name + "#" + f.Path, text: f.Content})
		}
	}
	return out
}

func TestShippedAgentConfigsPrivateTargetsFollowDeploymentProfile(t *testing.T) {
	root := repoRoot(t)
	configs := discoverAgentConfigs(t, root)

	seenSovereign := map[string]bool{}
	var hosted int
	for _, c := range configs {
		sovereign := sovereignAgentConfigs[c.name]
		if sovereign {
			seenSovereign[c.name] = true
		} else {
			hosted++
		}
		for _, v := range judgeAgentPrivateTargets(c.name, c.text, sovereign) {
			t.Error(v)
		}
	}
	// Non-vacuity: a rename or a walker bug must not empty either side.
	for name := range sovereignAgentConfigs {
		if !seenSovereign[name] {
			t.Errorf("%s: sovereign agent config not discovered under deploy/ (renamed? update sovereignAgentConfigs)", name)
		}
	}
	if hosted < 4 {
		t.Errorf("discovered only %d non-sovereign agent configs under deploy/; the walker lost the packaging/cloud-init/Ansible/example configs", hosted)
	}
}

// Any file under deploy/ outside the sovereign agent configs (Helm values and
// templates, Terraform, Ansible defaults, compose overlays) that turns the
// opt-in on is an MSP-hosted path doing it, which D-57 refuses.
func TestNoDeployFileOutsideSovereignConfigsOptsInToPrivateTargets(t *testing.T) {
	root := repoRoot(t)
	var scanned int
	err := filepath.WalkDir(filepath.Join(root, "deploy"), func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		name := filepath.ToSlash(strings.TrimPrefix(path, root+string(filepath.Separator)))
		if sovereignAgentConfigs[name] {
			return nil
		}
		b, rerr := os.ReadFile(path)
		if rerr != nil {
			return rerr
		}
		scanned++
		if m := allowPrivateTrueRe.FindString(string(b)); m != "" {
			t.Errorf("%s: %q — only the single-tenant (sovereign) agent configs may opt in to private targets (D-57)", name, strings.TrimSpace(m))
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk deploy/: %v", err)
	}
	if scanned < 50 {
		t.Fatalf("scanned only %d files under deploy/", scanned)
	}
}

// The opt-in is justified only because the eval stack is single-tenant: the
// control plane those canaries attach to must stay on the single profile.
func TestSovereignAgentConfigsRunBesideTheSingleProfile(t *testing.T) {
	for _, f := range sovereignStackFiles {
		text := readRepoFile(t, filepath.FromSlash(f))
		for _, m := range deploymentProfileRe.FindAllStringSubmatch(text, -1) {
			if m[1] != "single" {
				t.Errorf("%s sets PROBECTL_DEPLOYMENT_PROFILE=%s, but its canaries opt in to private targets because the stack is single-tenant (D-57)", f, m[1])
			}
		}
	}
	synthetic := readRepoFile(t, "deploy", "compose", "eval-synthetic.yml")
	for name := range sovereignAgentConfigs {
		mount := "./" + filepath.Base(name) + ":/etc/probectl/agent.yml"
		if !strings.Contains(synthetic, mount) {
			t.Errorf("eval-synthetic.yml no longer mounts %s (%q); a sovereign agent config that the single-profile stack does not run must not opt in", name, mount)
		}
	}
}

// Fail-before: each planted config is a regression the judges must catch.
func TestAgentPrivateTargetsJudgeCatchesPlantedRegressions(t *testing.T) {
	root := repoRoot(t)
	read := func(name string) string {
		b, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(plantedPrivateTargetsDir), name))
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	cases := []struct {
		file      string
		sovereign bool
		want      string
	}{
		{"hosted-flipped-true.yml", false, "only the single-tenant (sovereign) agent configs may opt in"},
		{"sovereign-flipped-false.yml", true, "must set test_sync.allow_private_targets: true explicitly"},
		{"sovereign-without-reason.yml", true, "must say why it is true"},
	}
	for _, tc := range cases {
		t.Run(tc.file, func(t *testing.T) {
			got := strings.Join(judgeAgentPrivateTargets(tc.file, read(tc.file), tc.sovereign), "\n")
			if !strings.Contains(got, tc.want) {
				t.Fatalf("planted %s was not caught (want %q), got: %q", tc.file, tc.want, got)
			}
		})
	}
	// A good sovereign config passes, so the planted failures are not just a
	// judge that refuses everything.
	if v := judgeAgentPrivateTargets("eval-agent.yml", readRepoFile(t, "deploy", "compose", "eval-agent.yml"), true); len(v) != 0 {
		t.Fatalf("the shipped sovereign config fails its own judge: %v", v)
	}
	// The whole-text scanner catches a Helm value or template turning it on.
	for _, planted := range []string{
		"testSync:\n  allow_private_targets: true\n",
		"    test_sync:\n      allow_private_targets: \"true\"\n",
		"allow_private_targets = true\n",
	} {
		if allowPrivateTrueRe.FindString(planted) == "" {
			t.Errorf("whole-text scan missed planted opt-in %q", planted)
		}
	}
	for _, fine := range []string{
		"  allow_private_targets: false\n",
		"  # allow_private_targets: true  (sovereign installs only)\n",
	} {
		if m := allowPrivateTrueRe.FindString(fine); m != "" {
			t.Errorf("whole-text scan flagged %q", fine)
		}
	}
	if m := deploymentProfileRe.FindStringSubmatch("      PROBECTL_DEPLOYMENT_PROFILE: multi-tenant\n"); m == nil || m[1] != "multi-tenant" {
		t.Errorf("profile scan missed a planted multi-tenant eval stack: %v", m)
	}
}
