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
