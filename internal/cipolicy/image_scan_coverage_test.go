// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package cipolicy

import (
	"regexp"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// TestEveryBuiltImageIsScanned closes SUP-01: every image the build-images job
// builds must also be vuln-scanned by the image-scan job. Before the fix,
// build-images built 12 images while image-scan trivy-scanned only
// probectl-control — eleven shipped images went unscanned, and nothing caught
// it. This asserts set(build-images components) ⊆ set(image-scan components), so
// adding a published image without a scan fails CI.
//
// Fail-before: with image-scan covering only probectl-control, every other
// build-images component is reported missing.
func TestEveryBuiltImageIsScanned(t *testing.T) {
	ci := readWorkflow(t, "ci.yml")
	built := matrixComponents(t, ci, "build-images")
	scanned := matrixComponents(t, ci, "image-scan")

	if len(built) < 10 {
		t.Fatalf("SUP-01: found only %d build-images components (%v) — the parser likely broke", len(built), built)
	}
	scanSet := map[string]bool{}
	for _, c := range scanned {
		scanSet[c] = true
	}
	var missing []string
	for _, c := range built {
		if !scanSet[c] {
			missing = append(missing, c)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		t.Errorf("SUP-01: these built images are NOT vuln-scanned by image-scan: %v (built=%v scanned=%v)", missing, built, scanned)
	}
}

// matrixComponents extracts the `component:` values from the matrix of one job
// block in a workflow file.
func matrixComponents(t *testing.T, wf, job string) []string {
	t.Helper()
	lines := strings.Split(wf, "\n")
	jobHead := regexp.MustCompile(`^  [A-Za-z0-9_-]+:\s*$`)
	comp := regexp.MustCompile(`component:\s*([A-Za-z0-9_-]+)`)
	start := -1
	for i, ln := range lines {
		if ln == "  "+job+":" {
			start = i
			break
		}
	}
	if start < 0 {
		t.Fatalf("job %q not found in workflow", job)
	}
	var out []string
	seen := map[string]bool{}
	for i := start + 1; i < len(lines); i++ {
		if jobHead.MatchString(lines[i]) { // next top-level job ends this block
			break
		}
		// Only count matrix include entries (list items), not build-args refs.
		if !strings.Contains(lines[i], "- {") && !strings.Contains(strings.TrimSpace(lines[i]), "- component:") {
			continue
		}
		if m := comp.FindStringSubmatch(lines[i]); m != nil && !seen[m[1]] {
			seen[m[1]] = true
			out = append(out, m[1])
		}
	}
	sort.Strings(out)
	return out
}

// TestEveryImageScanBlocks pins PD-13 (D-49): every image-scan row fails the job
// on a finding at its severity. The browser-agent row used to be report-only
// (exit_code "0"), so a fixable CRITICAL in its playwright base could ship; it now
// blocks on CRITICAL, and every other row on CRITICAL and HIGH.
func TestEveryImageScanBlocks(t *testing.T) {
	ci := readWorkflow(t, "ci.yml")
	lines := strings.Split(ci, "\n")
	start := -1
	for i, ln := range lines {
		if ln == "  image-scan:" {
			start = i
			break
		}
	}
	if start < 0 {
		t.Fatal("ci.yml has no image-scan job")
	}
	rows := 0
	for _, ln := range lines[start+1:] {
		if regexp.MustCompile(`^  [A-Za-z0-9_-]+:\s*$`).MatchString(ln) {
			break
		}
		if !strings.Contains(ln, "- {") {
			continue
		}
		rows++
		if !strings.Contains(ln, `exit_code: "1"`) {
			t.Errorf("image-scan row does not block on its findings (PD-13): %s", strings.TrimSpace(ln))
		}
		if strings.Contains(ln, "probectl-browser-agent") && !strings.Contains(ln, "severity: CRITICAL") {
			t.Errorf("the browser-agent scan must block on CRITICAL (PD-13/D-49): %s", strings.TrimSpace(ln))
		}
	}
	if rows < 10 {
		t.Fatalf("found only %d image-scan rows; the parser likely broke", rows)
	}
	if !strings.Contains(ci, "severity: ${{ matrix.severity || 'CRITICAL,HIGH' }}") {
		t.Error("the Trivy step no longer takes its severity from the row (PD-13)")
	}
}

func TestImageWorkWaitsForExistingEarlyBuilds(t *testing.T) {
	ci := readWorkflow(t, "ci.yml")
	needs := jobNeeds(t, ci)
	for _, job := range []string{"build-images", "image-scan", "e2e"} {
		for _, prerequisite := range []string{"no-devauth-in-release", "web-build"} {
			if !gatesOn(job, prerequisite, needs, map[string]bool{}) {
				t.Errorf("%s can start before existing %s compile checks", job, prerequisite)
			}
		}
	}
	var workflow struct {
		Jobs map[string]struct {
			Steps []struct {
				Run string `yaml:"run"`
			} `yaml:"steps"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal([]byte(ci), &workflow); err != nil {
		t.Fatal(err)
	}
	var commands []string
	for _, step := range workflow.Jobs["web-build"].Steps {
		commands = append(commands, step.Run)
	}
	for _, required := range []string{"npm run typecheck", "npm run build", "npm run bundle:check", "go test -tags release ./internal/webui/", "go build -trimpath -o /tmp/probectl-control-ui-check ./cmd/probectl-control"} {
		if !strings.Contains(strings.Join(commands, "\n"), required) {
			t.Errorf("early build lost existing check %q", required)
		}
	}
}

func TestImageConsumersReuseVerifiedProducerBytes(t *testing.T) {
	var workflow struct {
		Jobs map[string]struct {
			Steps []struct {
				Uses string            `yaml:"uses"`
				Run  string            `yaml:"run"`
				With map[string]string `yaml:"with"`
			} `yaml:"steps"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal([]byte(readWorkflow(t, "ci.yml")), &workflow); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"image-scan", "e2e"} {
		var commands []string
		for _, step := range workflow.Jobs[name].Steps {
			if strings.HasPrefix(step.Uses, "docker/build-push-action@") || strings.Contains(step.Run, "docker build") {
				t.Errorf("%s rebuilds the image instead of consuming the exact producer", name)
			}
			commands = append(commands, step.Run)
		}
		joined := strings.Join(commands, "\n")
		for _, required := range []string{"gh run download", "scripts/ci_image.py load", "--receipt", "--component", "--output artifacts/image-consumer/"} {
			if !strings.Contains(joined, required) {
				t.Errorf("%s lost verified image consumption %q", name, required)
			}
		}
	}
	var platforms []string
	for _, step := range workflow.Jobs["build-images"].Steps {
		if !strings.HasPrefix(step.Uses, "docker/build-push-action@") {
			continue
		}
		platforms = append(platforms, step.With["platforms"])
		if step.With["push"] != "false" || !strings.Contains(step.With["labels"], "org.opencontainers.image.revision=${{ github.sha }}") {
			t.Fatal("CI image exports must retain exact source identity and never publish")
		}
		switch step.With["platforms"] {
		case "linux/amd64,linux/arm64":
			if !strings.HasPrefix(step.With["outputs"], "type=oci,") || step.With["provenance"] != "mode=min" {
				t.Fatal("complete multiarch export/provenance is missing")
			}
		case "linux/amd64":
			if !strings.HasPrefix(step.With["outputs"], "type=docker,") {
				t.Fatal("consumer transfer must be single-platform Docker format")
			}
		default:
			t.Fatal("unexpected image export platform")
		}
	}
	if len(platforms) != 2 {
		t.Fatal("producer must retain both full multiarch build and cached amd64 export")
	}
}
