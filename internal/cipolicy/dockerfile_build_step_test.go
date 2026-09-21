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

// dockerfileBuildScript extracts the shell script of the Go build step (the
// RUN that compiles /out/app) from a Dockerfile, joining its continuation
// lines the way the Docker builder does.
func dockerfileBuildScript(t *testing.T, dockerfile string) string {
	t.Helper()
	lines := strings.Split(dockerfile, "\n")
	for i, line := range lines {
		if !strings.HasPrefix(line, "RUN --mount=type=cache,target=/root/.cache/go-build") {
			continue
		}
		var script []string
		for j := i; j < len(lines); j++ {
			l := strings.TrimSuffix(lines[j], "\\")
			if j == i {
				l = strings.TrimPrefix(l, "RUN --mount=type=cache,target=/root/.cache/go-build")
			}
			script = append(script, l)
			if !strings.HasSuffix(lines[j], "\\") {
				break
			}
		}
		// The builder drops each backslash-newline pair: the step is one line.
		return strings.Join(script, "")
	}
	t.Fatal("Dockerfile has no Go build RUN step")
	return ""
}

// runDockerBuildScript runs the build step under /bin/sh with a fake `go` on
// PATH that records its environment and arguments, exactly as the builder
// would invoke it, and returns what the fake saw.
func runDockerBuildScript(t *testing.T, script, gofips string) (seen string, err error) {
	t.Helper()
	dir := t.TempDir()
	record := filepath.Join(dir, "seen")
	fakeGo := "#!/bin/sh\n{ env; echo \"ARGS: $*\"; } > " + record + "\nexit 0\n"
	if err := os.WriteFile(filepath.Join(dir, "go"), []byte(fakeGo), 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("/bin/sh", "-c", script)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"PATH="+dir+":"+os.Getenv("PATH"),
		"GOFIPS140="+gofips, "GO_TAGS=probectl_fips",
		"TARGETOS=linux", "TARGETARCH=arm64", "COMPONENT=probectl-control",
		"VERSION=1.2.3", "DATE=2026-09-17T00:00:00Z", "COMMIT=abc", "LICENSE_PUBKEYS_B64=")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), err
	}
	b, rerr := os.ReadFile(record)
	if rerr != nil {
		t.Fatalf("the build step never invoked go: %v\n%s", rerr, out)
	}
	return string(b), nil
}

// TestDockerfileBuildStepHonoursGOFIPS140 (DPR-086 retest): the container
// build must hand GOFIPS140 to the Go toolchain when the build arg is set —
// the FIPS 140-3 image is produced from the shipped Dockerfile — and build
// normally when it is empty. The first attempt expanded the variable into a
// command word ("GOFIPS140=v1.0.0: not found"), which only a shell run catches.
func TestDockerfileBuildStepHonoursGOFIPS140(t *testing.T) {
	script := dockerfileBuildScript(t, readRepoFile(t, "deploy", "docker", "Dockerfile"))

	seen, err := runDockerBuildScript(t, script, "v1.0.0")
	if err != nil {
		t.Fatalf("build step failed with GOFIPS140 set: %v\n%s", err, seen)
	}
	if !strings.Contains(seen, "\nGOFIPS140=v1.0.0\n") {
		t.Fatalf("go must see GOFIPS140=v1.0.0 in its environment:\n%s", seen)
	}
	if !strings.Contains(seen, "-tags probectl_fips") || !strings.Contains(seen, "-o /out/app ./cmd/probectl-control") {
		t.Fatalf("go build arguments lost the tags or the output:\n%s", seen)
	}

	seen, err = runDockerBuildScript(t, script, "")
	if err != nil {
		t.Fatalf("build step failed with GOFIPS140 empty: %v\n%s", err, seen)
	}
	if strings.Contains(seen, "\nGOFIPS140=") && !strings.Contains(seen, "\nGOFIPS140=\n") {
		t.Fatalf("an empty GOFIPS140 must not turn FIPS on:\n%s", seen)
	}
}

// TestDockerfileBuildStepCatchesVariableAsCommand proves the harness sees the
// original mistake: a conditional expansion in command position is executed
// as a command, not an assignment.
func TestDockerfileBuildStepCatchesVariableAsCommand(t *testing.T) {
	broken := "set -eu; GOOS=${TARGETOS} CGO_ENABLED=0 ${GOFIPS140:+GOFIPS140=${GOFIPS140}} go build -o /out/app ./cmd/${COMPONENT}"
	if out, err := runDockerBuildScript(t, broken, "v1.0.0"); err == nil {
		t.Fatalf("the broken expansion must fail under sh, got success:\n%s", out)
	}
}
