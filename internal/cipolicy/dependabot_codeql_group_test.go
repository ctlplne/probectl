// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package cipolicy

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// TestDependabotGroupsEveryCodeQLSubAction keeps CodeQL's sub-actions moving
// as one unit. init writes a configuration that analyze refuses across versions
// ("Loaded a configuration file for version 3.38.2, but running version
// 4.38.2"), so when Dependabot opened one PR per sub-action every one of them
// failed CI — and merging any single one would have broken code scanning on
// main. Every codeql-action step any workflow uses must fall inside ONE
// github-actions group.
//
// Fail-before: the github-actions entry had no groups, so no group covered
// github/codeql-action/init, /autobuild or /analyze.
func TestDependabotGroupsEveryCodeQLSubAction(t *testing.T) {
	var cfg struct {
		Updates []struct {
			Ecosystem string `yaml:"package-ecosystem"`
			Directory string `yaml:"directory"`
			Groups    map[string]struct {
				Patterns []string `yaml:"patterns"`
			} `yaml:"groups"`
		} `yaml:"updates"`
	}
	if err := yaml.Unmarshal([]byte(readRepoFile(t, ".github", "dependabot.yml")), &cfg); err != nil {
		t.Fatalf("parse .github/dependabot.yml: %v", err)
	}

	// Every codeql-action sub-action any workflow actually uses.
	used := map[string]bool{}
	ref := regexp.MustCompile(`uses:\s*(github/codeql-action/[a-z-]+)@`)
	entries, err := os.ReadDir(filepath.Join(repoRoot(t), ".github", "workflows"))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yml") {
			continue
		}
		for _, m := range ref.FindAllStringSubmatch(readRepoFile(t, ".github", "workflows", e.Name()), -1) {
			used[m[1]] = true
		}
	}
	if len(used) < 2 {
		t.Fatalf("expected the workflows to use several github/codeql-action sub-actions, found %v", used)
	}

	// Dependabot patterns: "*" matches any run of characters, including "/".
	matches := func(pattern, dep string) bool {
		re := "^" + strings.ReplaceAll(regexp.QuoteMeta(pattern), `\*`, ".*") + "$"
		return regexp.MustCompile(re).MatchString(dep)
	}
	coveredByOneGroup := func(patterns []string) bool {
		for dep := range used {
			hit := false
			for _, p := range patterns {
				if matches(p, dep) {
					hit = true
					break
				}
			}
			if !hit {
				return false
			}
		}
		return true
	}
	for _, u := range cfg.Updates {
		if u.Ecosystem != "github-actions" || u.Directory != "/" {
			continue
		}
		for _, g := range u.Groups {
			if coveredByOneGroup(g.Patterns) {
				return
			}
		}
		t.Fatalf("no github-actions Dependabot group covers every CodeQL sub-action %v — they would be bumped in separate, version-skewed PRs", used)
	}
	t.Fatal(`.github/dependabot.yml has no github-actions update for directory "/"`)
}
