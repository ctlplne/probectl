// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package docs

import (
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// TQ-08: docs/development.md presents its CI-jobs table as "the full list;
// ci.yml is the source of truth" and "every pull request runs them". It listed
// four names (journey-e2e, test-integration-isolated, evidence-receipt-gate,
// release-claim-gate) that are Makefile targets, not ci.yml jobs — so the
// contract was a fiction. This test keeps the documented set EXACTLY equal to
// ci.yml's actual job keys, both directions, so the table can never drift from
// what CI runs again.
func TestDevelopmentDocCIJobsMatchWorkflow(t *testing.T) {
	actual := ciWorkflowJobs(t)
	documented := documentedCIJobs(t)

	var missing, extra []string
	for j := range documented {
		if !actual[j] {
			extra = append(extra, j) // documented but not a real ci.yml job
		}
	}
	for j := range actual {
		if !documented[j] {
			missing = append(missing, j) // a real job the docs omit
		}
	}
	sort.Strings(missing)
	sort.Strings(extra)
	if len(extra) > 0 {
		t.Errorf("docs/development.md CI-jobs table lists names that are not ci.yml jobs (TQ-08): %v", extra)
	}
	if len(missing) > 0 {
		t.Errorf("docs/development.md CI-jobs table omits real ci.yml jobs (TQ-08): %v", missing)
	}
}

// ciWorkflowJobs returns the set of top-level job keys under `jobs:` in ci.yml
// (two-space-indented `name:` lines), stopping at the next top-level key.
func ciWorkflowJobs(t *testing.T) map[string]bool {
	t.Helper()
	raw, err := os.ReadFile("../.github/workflows/ci.yml")
	if err != nil {
		t.Fatalf("read ci.yml: %v", err)
	}
	jobs := map[string]bool{}
	inJobs := false
	jobLine := regexp.MustCompile(`^  ([A-Za-z0-9_-]+):\s*$`)
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(line, "jobs:") {
			inJobs = true
			continue
		}
		if !inJobs {
			continue
		}
		if len(line) > 0 && line[0] != ' ' && line[0] != '\t' && line[0] != '#' {
			break // left the jobs: block
		}
		if m := jobLine.FindStringSubmatch(line); m != nil {
			jobs[m[1]] = true
		}
	}
	if len(jobs) == 0 {
		t.Fatal("parsed no jobs from ci.yml")
	}
	return jobs
}

// documentedCIJobs returns the job names in the first column of the CI-jobs
// table in development.md (within the "## CI jobs" section).
func documentedCIJobs(t *testing.T) map[string]bool {
	t.Helper()
	raw, err := os.ReadFile("development.md")
	if err != nil {
		t.Fatalf("read development.md: %v", err)
	}
	section := raw
	if i := strings.Index(string(raw), "## CI jobs"); i >= 0 {
		section = raw[i:]
	}
	// Stop at the next top-level section so later `| `x` |` tables don't leak in.
	if j := strings.Index(string(section[len("## CI jobs"):]), "\n## "); j >= 0 {
		section = section[:len("## CI jobs")+j]
	}
	row := regexp.MustCompile("(?m)^\\|\\s*`([A-Za-z0-9_-]+)`\\s*\\|")
	docs := map[string]bool{}
	for _, m := range row.FindAllStringSubmatch(string(section), -1) {
		docs[m[1]] = true
	}
	if len(docs) == 0 {
		t.Fatal("parsed no documented jobs from development.md")
	}
	return docs
}
