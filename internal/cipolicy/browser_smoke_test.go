// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package cipolicy

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestBrowserSmokeBuildsItsInputAndStopsOnBuildFailure(t *testing.T) {
	for _, failBuild := range []bool{false, true} {
		name := "success"
		if failBuild {
			name = "build-failure"
		}
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			calls := filepath.Join(dir, "calls")
			mock := `#!/bin/sh
printf '%s\n' "$*" >> "$QA_DOCKER_CALLS"
if [ "$1" = build ] && [ "$QA_FAIL_BUILD" = 1 ]; then exit 17; fi
`
			if err := os.WriteFile(filepath.Join(dir, "docker"), []byte(mock), 0o700); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command("bash", filepath.Join(repoRoot(t), "scripts/check_browser_image.sh"), "probectl-qa-codex-smoke:test", "linux/arm64")
			cmd.Env = append(os.Environ(), "PATH="+dir+string(os.PathListSeparator)+os.Getenv("PATH"), "QA_DOCKER_CALLS="+calls)
			if failBuild {
				cmd.Env = append(cmd.Env, "QA_FAIL_BUILD=1")
			}
			output, err := cmd.CombinedOutput()
			raw, readErr := os.ReadFile(calls)
			if readErr != nil {
				t.Fatal(readErr)
			}
			lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
			if !strings.HasPrefix(lines[0], "build ") {
				t.Fatalf("smoke ran an externally supplied image without building it: %s", raw)
			}
			for _, flag := range []string{"--platform linux/arm64", "--build-arg COMPONENT=probectl-agent", "--build-arg EDITION=core", "deploy/docker/Dockerfile.browser-agent", "-t probectl-qa-codex-smoke:test"} {
				if !strings.Contains(lines[0], flag) {
					t.Errorf("build missing %q: %s", flag, lines[0])
				}
			}
			if failBuild {
				if err == nil || len(lines) != 1 {
					t.Fatalf("failed build must prevent smoke execution: err=%v calls=%s output=%s", err, raw, output)
				}
				return
			}
			if err != nil {
				t.Fatalf("smoke failed: %v %s", err, output)
			}
			if len(lines) != 2 {
				t.Fatalf("want build then smoke; got %s", raw)
			}
			for _, flag := range []string{"run ", "--pull never", "--network none", "--entrypoint node", "probectl-qa-codex-smoke:test /worker/smoke.mjs"} {
				if !strings.Contains(lines[1], flag) {
					t.Errorf("smoke missing %q: %s", flag, lines[1])
				}
			}
		})
	}
}
