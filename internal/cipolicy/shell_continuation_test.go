// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package cipolicy

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// TestNoCommentInsideAShellContinuation (DPR-225): a `#` line directly after a
// line ending in `\` silently splits the command in two. The backslash joins the
// next line, the `#` then comments out the rest of it, and everything before the
// comment becomes a bare assignment statement that runs nothing and exits 0.
//
// This is not hypothetical. DPR-207 documented its own fix with a comment placed
// mid-chain in ci.yml's failover-drill step, which left
// check_drill_evidence.sh running with one of its six variables set — defaulting
// to SCOPE=all, CHECK_DOCS=1 and the committed docs paths instead of the run's
// artifacts. Nothing complains: shellcheck does not see YAML `run:` blocks, the
// YAML still parses, and the step's exit status is the checker's, so the wrong
// check just fails for the wrong reason (or, with a laxer command, passes).
//
// Proved before this guard was written:
//
//	A=1 \
//	  B=2 \
//	  # comment
//	  C=3 \
//	  env
//
// runs `C=3 env`; A and B are set in the shell and never reach the child.
//
// The remedy is always the same and costs nothing: put the comment above the
// command. So the rule is mechanical — no comment line may follow a
// continuation — and it covers every workflow and shell script in the repo, not
// just the step that taught us.
func TestNoCommentInsideAShellContinuation(t *testing.T) {
	root := repoRoot(t)
	var scanned int
	var violations []string
	for _, rel := range continuationScanTargets(t, root) {
		body, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		scanned++
		violations = append(violations, commentAfterContinuation(rel, string(body))...)
	}
	if scanned < 20 {
		t.Fatalf("scanned only %d files; the guard's reach collapsed", scanned)
	}
	if len(violations) != 0 {
		t.Fatalf("a comment directly after a `\\` continuation splits the command — move it above:\n  %s",
			strings.Join(violations, "\n  "))
	}
}

// TestCommentAfterContinuationDetectorCatchesThePlantedShape is the guard's own
// self-test: the real ci.yml shape it missed, and the shapes it must leave alone.
func TestCommentAfterContinuationDetectorCatchesThePlantedShape(t *testing.T) {
	for name, tc := range map[string]struct {
		src  string
		want int
	}{
		"the DPR-207 shape": {
			src: "          PROBECTL_DRILL_SCOPE=failover \\\n" +
				"            PROBECTL_DRILL_CHECK_DOCS=0 \\\n" +
				"            # the drill names its profile ci-dev-compose-<mode>\n" +
				"            PROBECTL_DRILL_FAILOVER_PROFILES=ci-dev-compose-sync \\\n" +
				"            bash scripts/check_drill_evidence.sh\n",
			want: 1,
		},
		"comment above the chain is fine": {
			src: "          # the drill names its profile ci-dev-compose-<mode>\n" +
				"          A=1 \\\n            B=2 \\\n            cmd\n",
			want: 0,
		},
		"a blank line between does not rescue it": {
			src:  "          A=1 \\\n\n          # still the same mistake, one line further down\n          cmd\n",
			want: 1,
		},
		"a backslash inside a quoted string is not a continuation": {
			src:  "          printf 'a\\tb'\n          # a following comment is fine\n          cmd\n",
			want: 0,
		},
		"an escaped newline in a YAML literal comment is not code": {
			src:  "          cmd one\n          cmd two\n",
			want: 0,
		},
	} {
		if got := commentAfterContinuation("planted", tc.src); len(got) != tc.want {
			t.Errorf("%s: detector found %d violations %v, want %d", name, len(got), got, tc.want)
		}
	}
}

// commentAfterContinuation returns "rel:line" for every comment line that
// directly follows a line ending in an unescaped `\`, skipping blank lines in
// between (they do not terminate the continuation either).
func commentAfterContinuation(rel, body string) []string {
	var out []string
	pending := false
	pendingLine := 0
	for i, line := range strings.Split(body, "\n") {
		trimmed := strings.TrimSpace(line)
		if pending {
			if trimmed == "" {
				continue // still inside the continuation
			}
			if strings.HasPrefix(trimmed, "#") {
				out = append(out, rel+":"+strconv.Itoa(i+1)+" (continues line "+strconv.Itoa(pendingLine)+")")
			}
		}
		pending = endsInContinuation(trimmed)
		pendingLine = i + 1
	}
	return out
}

// endsInContinuation reports whether the line ends in a line-continuation
// backslash rather than a literal one (`printf 'a\\'` ends in an escaped
// backslash, which is not a continuation).
func endsInContinuation(trimmed string) bool {
	if !strings.HasSuffix(trimmed, `\`) {
		return false
	}
	n := 0
	for i := len(trimmed) - 1; i >= 0 && trimmed[i] == '\\'; i-- {
		n++
	}
	return n%2 == 1
}

// continuationScanTargets lists the workflows and shell scripts to scan:
// everything under .github/workflows plus every *.sh in the repo, excluding
// vendored and generated trees.
func continuationScanTargets(t *testing.T, root string) []string {
	t.Helper()
	var out []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", "third_party", "dist", "bin":
				return filepath.SkipDir
			}
			return nil
		}
		rel, rerr := filepath.Rel(root, path)
		if rerr != nil {
			return rerr
		}
		rel = filepath.ToSlash(rel)
		switch {
		case strings.HasPrefix(rel, ".github/workflows/") && strings.HasSuffix(rel, ".yml"),
			strings.HasSuffix(rel, ".sh"):
			out = append(out, rel)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk repo: %v", err)
	}
	return out
}

// TestContainerJobStepsDeclareBashWhenTheyUseIt (DPR-233): inside a `container:`
// job a `run:` block's default shell is `sh`, which on Debian/Ubuntu images is
// dash. Bash-only syntax there does not degrade — the step dies immediately with
// "Illegal option -o pipefail", before running anything it was meant to run.
//
// DPR-222 added a `set -euo pipefail` guard to the browser-worker job, which runs
// in the pinned Playwright image, and turned that job from green into a step that
// never executed its own test. So the rule is mechanical: a step in a container
// job whose script uses bash-only syntax must declare `shell: bash` (or the job
// must default to it).
func TestContainerJobStepsDeclareBashWhenTheyUseIt(t *testing.T) {
	// Bash-only constructs that dash rejects outright.
	bashOnly := []string{"pipefail", "[[", "<<<", "PIPESTATUS", "function ", "local -", "declare -"}
	var violations []string
	checked := 0
	for _, rel := range containerJobWorkflows(t) {
		body := readRepoFile(t, ".github", "workflows", rel)
		for _, job := range containerJobBlocks(body) {
			if jobDefaultsToBash(job.text) {
				continue
			}
			checked++
			for _, st := range runBlocks(job.text) {
				if declaresShell(st.text) {
					continue
				}
				for _, tok := range bashOnly {
					if strings.Contains(st.script, tok) {
						violations = append(violations,
							rel+" job "+job.name+" step at line "+strconv.Itoa(st.line)+" uses "+strconv.Quote(tok))
						break
					}
				}
			}
		}
	}
	if checked == 0 {
		t.Fatal("found no container jobs to check; the guard's reach collapsed")
	}
	if len(violations) != 0 {
		t.Fatalf("a container job's default shell is sh (dash) — add `shell: bash` to these steps:\n  %s",
			strings.Join(violations, "\n  "))
	}
}

type ciJob struct {
	name string
	text string
}

type ciStep struct {
	line   int
	text   string
	script string
}

// containerJobWorkflows lists the workflow files that declare at least one
// container job.
func containerJobWorkflows(t *testing.T) []string {
	t.Helper()
	dir := filepath.Join(repoRoot(t), ".github", "workflows")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read workflows: %v", err)
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yml") {
			continue
		}
		b, rerr := os.ReadFile(filepath.Join(dir, e.Name()))
		if rerr != nil {
			t.Fatalf("read %s: %v", e.Name(), rerr)
		}
		if strings.Contains(string(b), "\n    container:") {
			out = append(out, e.Name())
		}
	}
	return out
}

// containerJobBlocks splits a workflow into its jobs and returns only those
// declaring a container.
func containerJobBlocks(body string) []ciJob {
	var out []ciJob
	lines := strings.Split(body, "\n")
	starts := []int{}
	names := []string{}
	for i, ln := range lines {
		if len(ln) > 2 && ln[0] == ' ' && ln[1] == ' ' && ln[2] != ' ' && strings.HasSuffix(strings.TrimRight(ln, " "), ":") {
			starts = append(starts, i)
			names = append(names, strings.TrimSuffix(strings.TrimSpace(ln), ":"))
		}
	}
	for i, s := range starts {
		e := len(lines)
		if i+1 < len(starts) {
			e = starts[i+1]
		}
		text := strings.Join(lines[s:e], "\n")
		if strings.Contains(text, "\n    container:") {
			out = append(out, ciJob{name: names[i], text: text})
		}
	}
	return out
}

// jobDefaultsToBash reports whether the job sets bash as its default run shell.
func jobDefaultsToBash(job string) bool {
	i := strings.Index(job, "\n    defaults:")
	if i < 0 {
		return false
	}
	window := job[i:]
	if j := strings.Index(window[1:], "\n    "); j > 0 {
		// Stay inside the defaults: block plus its nested lines.
		for _, ln := range strings.Split(window, "\n") {
			t := strings.TrimSpace(ln)
			if strings.HasPrefix(t, "shell:") {
				return strings.Contains(t, "bash")
			}
		}
	}
	return false
}

// runBlocks returns each `run:` script in a job, with the line it starts on.
func runBlocks(job string) []ciStep {
	var out []ciStep
	lines := strings.Split(job, "\n")
	for i, ln := range lines {
		t := strings.TrimSpace(ln)
		if t != "run: |" && !strings.HasPrefix(t, "run: |") && !strings.HasPrefix(t, "run: ") {
			continue
		}
		indent := len(ln) - len(strings.TrimLeft(ln, " "))
		script := t
		// A block scalar's body is every following line indented deeper.
		for j := i + 1; j < len(lines); j++ {
			nxt := lines[j]
			if strings.TrimSpace(nxt) == "" {
				continue
			}
			if len(nxt)-len(strings.TrimLeft(nxt, " ")) <= indent {
				break
			}
			script += "\n" + nxt
		}
		// The step's own keys, for the shell: lookup.
		stepStart := i
		for stepStart > 0 && !strings.HasPrefix(strings.TrimSpace(lines[stepStart]), "- ") {
			stepStart--
		}
		stepEnd := i
		for stepEnd+1 < len(lines) {
			nxt := lines[stepEnd+1]
			if strings.HasPrefix(strings.TrimSpace(nxt), "- ") && len(nxt)-len(strings.TrimLeft(nxt, " ")) <= indent {
				break
			}
			stepEnd++
		}
		out = append(out, ciStep{
			line:   i + 1,
			text:   strings.Join(lines[stepStart:stepEnd+1], "\n"),
			script: script,
		})
	}
	return out
}

// declaresShell reports whether a step sets its own shell.
func declaresShell(step string) bool {
	for _, ln := range strings.Split(step, "\n") {
		if strings.HasPrefix(strings.TrimSpace(ln), "shell:") {
			return true
		}
	}
	return false
}

// workflowFiles lists every workflow yml by name.
func workflowFiles(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(repoRoot(t), ".github", "workflows"))
	if err != nil {
		t.Fatalf("read workflows: %v", err)
	}
	var out []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".yml") {
			out = append(out, e.Name())
		}
	}
	return out
}
