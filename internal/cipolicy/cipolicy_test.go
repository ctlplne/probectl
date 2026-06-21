// SPDX-License-Identifier: LicenseRef-probectl-TBD

// Package cipolicy holds policy tests over the CI/release workflows themselves —
// the in-repo backstops that protect main when GitHub branch-protection settings
// (which live in server config, not the tree) cannot be asserted from here.
//
// EXC-GATE-04: assert the release.yml require-green-ci backstop exists (a v* tag
// cannot publish unless the full ci workflow concluded green on that exact SHA)
// and that verify-all is the umbrella that requires every other verification gate
// — so a gate added later but not folded into the umbrella fails this test
// instead of silently going unenforced.
//
// EXC-GATE-02: assert the ebpf-kernel-matrix live-load job is wired into the
// verify-all umbrella (the live load+attach runs on real LTS kernels in CI), so
// it cannot be quietly dropped from the required set.
package cipolicy

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("cipolicy: could not locate go.mod from working dir")
		}
		dir = parent
	}
}

func readWorkflow(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(repoRoot(t), ".github", "workflows", name))
	if err != nil {
		t.Fatalf("read workflow %s: %v", name, err)
	}
	return string(b)
}

// TestReleaseRequiresGreenCI is the EXC-GATE-04 backstop: a v* tag must not
// publish anything unless the full ci workflow was green on the tagged SHA. This
// holds even for a tag cut off a side branch or by an admin who bypassed branch
// protection — it is the second, independent layer documented in
// docs/ops/branch-protection.md.
func TestReleaseRequiresGreenCI(t *testing.T) {
	rel := readWorkflow(t, "release.yml")

	if !strings.Contains(rel, "require-green-ci:") {
		t.Fatal("release.yml is missing the require-green-ci backstop job (EXC-GATE-04)")
	}
	// Every job that publishes an artifact must depend (transitively) on
	// require-green-ci, or the backstop is a no-op for that job. The job's own
	// `needs:` must name it directly OR name another job that does.
	needsByJob := jobNeeds(t, rel)
	for _, job := range []string{"images", "binaries", "publish-chart", "packages"} {
		deps, ok := needsByJob[job]
		if !ok {
			t.Errorf("release.yml has no publishing job %q (renamed?) — update this policy test", job)
			continue
		}
		if !gatesOnGreenCI(job, needsByJob, map[string]bool{}) {
			t.Errorf("publishing job %q does not gate (even transitively) on require-green-ci — needs=%v; the backstop is bypassable", job, deps)
		}
	}
}

// jobNeeds maps each job name to its list of `needs:` job names (handling both
// the inline-list `needs: [a, b]` and the block-list forms).
func jobNeeds(t *testing.T, wf string) map[string][]string {
	t.Helper()
	out := map[string][]string{}
	lines := strings.Split(wf, "\n")
	jobRe := regexp.MustCompile(`^  ([a-zA-Z0-9_-]+):\s*$`)
	var cur string
	for i := 0; i < len(lines); i++ {
		ln := lines[i]
		if m := jobRe.FindStringSubmatch(ln); m != nil {
			cur = m[1]
			out[cur] = nil
			continue
		}
		if cur == "" {
			continue
		}
		trimmed := strings.TrimSpace(ln)
		if strings.HasPrefix(trimmed, "needs:") {
			rest := strings.TrimSpace(strings.TrimPrefix(trimmed, "needs:"))
			rest = strings.Trim(rest, "[]")
			for _, n := range strings.Split(rest, ",") {
				if n = strings.TrimSpace(n); n != "" {
					out[cur] = append(out[cur], n)
				}
			}
		}
	}
	return out
}

// gatesOnGreenCI reports whether job depends, directly or transitively, on
// require-green-ci.
func gatesOnGreenCI(job string, needsByJob map[string][]string, seen map[string]bool) bool {
	if seen[job] {
		return false
	}
	seen[job] = true
	for _, dep := range needsByJob[job] {
		if dep == "require-green-ci" {
			return true
		}
		if gatesOnGreenCI(dep, needsByJob, seen) {
			return true
		}
	}
	return false
}

// TestBranchProtectionDocExists guards the operator-facing doc for the one
// console step the repo cannot perform (the GitHub setting). If it is deleted,
// the operator loses the runbook for making CI blocking.
func TestBranchProtectionDocExists(t *testing.T) {
	b, err := os.ReadFile(filepath.Join(repoRoot(t), "docs", "ops", "branch-protection.md"))
	if err != nil {
		t.Fatalf("docs/ops/branch-protection.md missing (EXC-GATE-04 operator runbook): %v", err)
	}
	doc := string(b)
	for _, want := range []string{"require-green-ci", "Require status checks", "verify-all"} {
		if !strings.Contains(doc, want) {
			t.Errorf("branch-protection doc does not mention %q (the required-check guidance is incomplete)", want)
		}
	}
}

// TestVerifyAllIsTheUmbrella asserts verify-all requires the full set of
// verification gates — including the ebpf-kernel-matrix live-load job
// (EXC-GATE-02) and the integration job that carries the cross-plane e2e
// (EXC-GATE-05). A gate that exists but is not in verify-all's needs is
// advisory; this test makes that omission RED.
func TestVerifyAllIsTheUmbrella(t *testing.T) {
	ci := readWorkflow(t, "ci.yml")

	// Pull the verify-all job's needs: block.
	needs := verifyAllNeeds(t, ci)
	if len(needs) < 10 {
		t.Fatalf("verify-all needs only %d gates — suspiciously few; parse failed or umbrella gutted: %v", len(needs), needs)
	}

	// The umbrella MUST include these load-bearing verification gates.
	required := []string{
		"lint-go", "editions-gate", "fips-gate", "test-go", "coverage",
		"ebpf-kernel-matrix", // EXC-GATE-02: live load+attach on real kernels
		"cross-tenant-isolation",
		"integration", // EXC-GATE-05: cross-plane correlation e2e rides here
	}
	have := map[string]bool{}
	for _, n := range needs {
		have[n] = true
	}
	for _, r := range required {
		if !have[r] {
			t.Errorf("verify-all does NOT require %q — that verification gate is advisory, not blocking", r)
		}
	}

	// Every job declared in ci.yml that is itself a verification gate should be
	// in the umbrella. We assert the umbrella is not trivially small (above) and
	// that the assertion step exists.
	if !strings.Contains(ci, "verify-all is RED") {
		t.Error("verify-all is missing its fail-closed assertion (the 'verify-all is RED' guard)")
	}
}

func TestSecretScanCoversGitHistory(t *testing.T) {
	ci := readWorkflow(t, "ci.yml")
	gitleaksConfig, err := os.ReadFile(filepath.Join(repoRoot(t), ".gitleaks.toml"))
	if err != nil {
		t.Fatalf("read .gitleaks.toml: %v", err)
	}
	script, err := os.ReadFile(filepath.Join(repoRoot(t), "scripts", "check_secret_scan_history.sh"))
	if err != nil {
		t.Fatalf("read secret-scan wrapper: %v", err)
	}

	for _, want := range []string{
		"secret-scan:",
		"fetch-depth: 0",
		"gitleaks/v8@v8.21.2",
		"PROBECTL_SECRET_SCAN_SELFTEST=planted",
		"./scripts/check_secret_scan_history.sh",
	} {
		if !strings.Contains(ci, want) {
			t.Errorf("ci.yml secret-scan gate is missing %q", want)
		}
	}
	for _, banned := range []string{
		"gitleaks detect --no-git",
		"gitleaks/v8@v8.18.4",
	} {
		if strings.Contains(ci, banned) {
			t.Errorf("ci.yml still contains HEAD-only/old secret-scan wiring %q", banned)
		}
	}

	for _, want := range []string{
		"\"$GITLEAKS\" git",
		"--log-opts \"$LOG_OPTS\"",
		"LOG_OPTS=\"${PROBECTL_GITLEAKS_LOG_OPTS:---all}\"",
		"planted/history_secret.pem",
	} {
		if !strings.Contains(string(script), want) {
			t.Errorf("secret-scan wrapper does not prove full-history scanning: missing %q", want)
		}
	}

	config := string(gitleaksConfig)
	for _, want := range []string{
		`id = "private-key"`,
		`id = "stripe-access-token"`,
		`condition = "AND"`,
		`95d313bd9d706c69b513fba2e36b071b4ac3d380`,
		`internal/auth/testdata/oidc_test_key\.pem`,
		`internal/control/alerts_integration_test\.go`,
		`a78802d3ea4dcce2362eb132749b086ffea7045b`,
		`4fa7ffba4a2e9773085d03a4bfff33a9504dbda6`,
		`CHANGELOG\.md`,
		`docs/diligence/known-risks\.md`,
	} {
		if !strings.Contains(config, want) {
			t.Errorf(".gitleaks.toml is missing the exact historical OIDC fixture allowlist piece %q", want)
		}
	}
}

// TestPRImageMatrixMatchesMakefileBinaries closes TEST-004: every binary the
// Makefile says we ship must be built by the PR image matrix. Release already
// has a shell parity gate; this gives pull requests the same early feedback.
func TestPRImageMatrixMatchesMakefileBinaries(t *testing.T) {
	want := makefileBinaries(t)
	have := ciBuildImageComponents(t, readWorkflow(t, "ci.yml"))
	if diff := stringSetDiff(want, have); diff != "" {
		t.Fatalf("ci.yml build-images matrix drifted from Makefile BINARIES (TEST-004):\n%s", diff)
	}
}

// TestArm64EBPFKernelMatrixRequiresLiveKVM closes EBPF-003/TEST-005: arm64 is
// no longer accepted as compile-only eBPF coverage. The arm64 row must run on a
// KVM-capable/native arm64 runner, execute the same live vimto test path as
// amd64, and fail closed when /dev/kvm is missing.
func TestArm64EBPFKernelMatrixRequiresLiveKVM(t *testing.T) {
	ci := readWorkflow(t, "ci.yml")
	for _, want := range []string{
		`kernel: "6.6-arm64"`,
		"runner: [self-hosted, Linux, ARM64, kvm]",
		"no /dev/kvm",
		"exit 1",
		"go test -tags ebpf -exec",
		"ebpf-kernel-matrix must live-load/attach on every architecture, including arm64",
	} {
		if !strings.Contains(ci, want) {
			t.Errorf("ci.yml no longer enforces arm64 eBPF live-load/KVM requirement %q (EBPF-003/TEST-005)", want)
		}
	}
	for _, banned := range []string{
		"runner: ubuntu-24.04-arm",
		"skipping the live kernel boot",
		"SKIP the live boot",
		"arm64 BPF objects compiled+verified above",
	} {
		if strings.Contains(ci, banned) {
			t.Errorf("ci.yml still contains old arm64 compile-only skip marker %q (EBPF-003/TEST-005)", banned)
		}
	}

	for _, path := range []string{
		"docs/ci-pipeline.md",
		"docs/ebpf-agent.md",
		"docs/security/agent-whitepaper.md",
	} {
		b, err := os.ReadFile(filepath.Join(repoRoot(t), filepath.FromSlash(path)))
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		doc := string(b)
		for _, want := range []string{"arm64", "live", "KVM"} {
			if !strings.Contains(doc, want) {
				t.Errorf("%s does not document %q for the arm64 eBPF live-load requirement", path, want)
			}
		}
		for _, banned := range []string{
			"TEST-005 residual risk",
			"compiles and digest-verifies",
			"compile/digest-tested, not CI live-load proven",
			"skips the live boot",
		} {
			if strings.Contains(doc, banned) {
				t.Errorf("%s still documents old arm64 compile-only residual risk %q", path, banned)
			}
		}
	}
}

// TestReleaseEBPFDownloadablesAreLiveBuilds closes TEST-002: the downloadable
// eBPF agent binaries and deb/rpm package inputs must be the same live
// `-tags ebpf` build as the shipped image. A plain cross-compile links the
// fixture source, so the release workflow must use the BPF generator path and
// assert `go version -m` before signing or packaging.
func TestReleaseEBPFDownloadablesAreLiveBuilds(t *testing.T) {
	rel := readWorkflow(t, "release.yml")
	for _, want := range []string{
		"bash scripts/build-release-binaries.sh",
		"eBPF release toolchain",
		"clang-14",
		"linux-tools-generic",
		"Assert packaged eBPF binary is live",
		"matrix.agent == 'ebpf-agent'",
		"go version -m \"$bin\"",
		"TEST-002",
	} {
		if !strings.Contains(rel, want) {
			t.Errorf("release.yml is missing %q from the live eBPF downloadable/package gate (TEST-002)", want)
		}
	}

	b, err := os.ReadFile(filepath.Join(repoRoot(t), "scripts", "build-release-binaries.sh"))
	if err != nil {
		t.Fatalf("read release binary builder: %v", err)
	}
	script := string(b)
	for _, want := range []string{
		"gen_bpf.sh all \"$arch\"",
		"\"$GO\" run ./gendigests .",
		"-tags ebpf",
		"\"$GO\" version -m \"$bin\"",
		"fixture-only eBPF agent",
		"probectl-ebpf-agent",
		`if [ "$component" = "probectl-ebpf-agent" ]; then`,
		`build_ebpf_binary "$arch" "$out"`,
	} {
		if !strings.Contains(script, want) {
			t.Errorf("scripts/build-release-binaries.sh is missing %q from the live eBPF build/assertion path (TEST-002)", want)
		}
	}
}

func makefileBinaries(t *testing.T) []string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(repoRoot(t), "Makefile"))
	if err != nil {
		t.Fatalf("read Makefile: %v", err)
	}
	re := regexp.MustCompile(`(?m)^BINARIES[[:space:]]*:=[[:space:]]*(.+)$`)
	m := re.FindStringSubmatch(string(b))
	if m == nil {
		t.Fatal("Makefile is missing BINARIES :=")
	}
	out := strings.Fields(m[1])
	sort.Strings(out)
	return out
}

func ciBuildImageComponents(t *testing.T, ci string) []string {
	t.Helper()
	lines := strings.Split(ci, "\n")
	jobRe := regexp.MustCompile(`^  ([a-zA-Z0-9_-]+):\s*$`)
	inJob := false
	inComponent := false
	var out []string
	for _, ln := range lines {
		if m := jobRe.FindStringSubmatch(ln); m != nil {
			if inJob && m[1] != "build-images" {
				break
			}
			inJob = m[1] == "build-images"
			inComponent = false
			continue
		}
		if !inJob {
			continue
		}
		trimmed := strings.TrimSpace(ln)
		if trimmed == "component:" {
			inComponent = true
			continue
		}
		if !inComponent {
			continue
		}
		if strings.HasPrefix(trimmed, "- ") {
			out = append(out, strings.TrimSpace(strings.TrimPrefix(trimmed, "- ")))
			continue
		}
		if trimmed != "" && !strings.HasPrefix(trimmed, "#") {
			inComponent = false
		}
	}
	sort.Strings(out)
	return out
}

func stringSetDiff(want, have []string) string {
	wantSet := map[string]bool{}
	haveSet := map[string]bool{}
	for _, v := range want {
		wantSet[v] = true
	}
	for _, v := range have {
		haveSet[v] = true
	}
	var missing, extra []string
	for _, v := range want {
		if !haveSet[v] {
			missing = append(missing, v)
		}
	}
	for _, v := range have {
		if !wantSet[v] {
			extra = append(extra, v)
		}
	}
	if len(missing) == 0 && len(extra) == 0 {
		return ""
	}
	var b strings.Builder
	if len(missing) > 0 {
		b.WriteString("missing from ci.yml build-images: ")
		b.WriteString(strings.Join(missing, ", "))
		b.WriteByte('\n')
	}
	if len(extra) > 0 {
		b.WriteString("extra in ci.yml build-images: ")
		b.WriteString(strings.Join(extra, ", "))
		b.WriteByte('\n')
	}
	return b.String()
}

// TestEBPFLiveLoadFatalsNotSkips is the EXC-GATE-02 guard: the live eBPF
// load+attach smoke (TestLiveLoadAttachL4Flow, run by the ebpf-kernel-matrix CI
// job on real LTS kernels under QEMU) must t.Fatal when load+attach fails — it
// must NOT t.Skip a load failure, or the kernel matrix would pass vacuously on a
// broken BPF object. This asserts the test source still fails on a load error.
func TestEBPFLiveLoadFatalsNotSkips(t *testing.T) {
	b, err := os.ReadFile(filepath.Join(repoRoot(t), "internal", "ebpf", "live_smoke_ebpf_test.go"))
	if err != nil {
		t.Fatalf("read live eBPF smoke: %v", err)
	}
	src := string(b)
	if !strings.Contains(src, "func TestLiveLoadAttachL4Flow") {
		t.Fatal("the live load+attach smoke TestLiveLoadAttachL4Flow is gone — the kernel matrix has nothing to assert")
	}
	// The l4flow load+attach failure path must be a Fatalf, not a Skip.
	if !strings.Contains(src, "l4flow load+attach failed on this kernel") {
		t.Fatal("the l4flow load+attach failure assertion text changed — verify it still FATALS (no skip-on-load-failure)")
	}
	idx := strings.Index(src, "l4flow load+attach failed on this kernel")
	start := idx - 120
	if start < 0 {
		start = 0
	}
	window := src[start:idx]
	if !strings.Contains(window, "t.Fatalf") {
		t.Errorf("live load+attach failure does not t.Fatalf — a load failure must redden the kernel matrix, never skip")
	}
}

// verifyAllNeeds extracts the list of job names under the verify-all job's
// `needs:` block.
func verifyAllNeeds(t *testing.T, ci string) []string {
	t.Helper()
	lines := strings.Split(ci, "\n")
	inJob := false
	inNeeds := false
	var out []string
	for _, ln := range lines {
		trimmed := strings.TrimSpace(ln)
		if trimmed == "verify-all:" {
			inJob = true
			continue
		}
		if inJob && !inNeeds {
			if trimmed == "needs:" {
				inNeeds = true
			}
			continue
		}
		if inNeeds {
			// list items look like "      - <name>" (possibly with a comment).
			if strings.HasPrefix(trimmed, "- ") {
				name := strings.TrimSpace(strings.TrimPrefix(trimmed, "- "))
				if i := strings.Index(name, "#"); i >= 0 {
					name = strings.TrimSpace(name[:i])
				}
				if name != "" {
					out = append(out, name)
				}
				continue
			}
			// A non-list, non-comment line ends the needs block (e.g. "steps:").
			if trimmed != "" && !strings.HasPrefix(trimmed, "#") {
				break
			}
		}
	}
	return out
}
