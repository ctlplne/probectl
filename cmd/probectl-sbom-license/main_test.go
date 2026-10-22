// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// The fixture is real syft 1.36.0 output (anchore/syft:v1.36.0, the version
// release.yml's sbom-action pins) over a release-shaped dist/ holding a
// linux/arm64 probectl-agent, trimmed to that binary's first-party package,
// one third-party module syft could not license, the Go stdlib syft licensed
// BSD-3-Clause, the scanned-directory root and their relationships (package
// checksums dropped).
const fixture = "testdata/syft-1.36.0-dist.spdx.json"

func TestTreeLicense(t *testing.T) {
	for path, want := range map[string]string{
		"ee/provider/openapi.json":      licenseCommercial,
		"ee/billing/billing.go":         licenseCommercial,
		"pkg/sdk/sdk.gen.go":            licenseClient,
		"proto/probectl/v1/x.proto":     licenseClient,
		"examples/sdk/list_tests.go":    licenseClient,
		"internal/webui/dist/index.js":  licenseCore,
		"cmd/probectl-agent/main.go":    licenseCore,
		"eex/not-ee.go":                 licenseCore,
		"internal/pkg/not-client.go":    licenseCore,
		"README.md":                     licenseCore,
		"web/src/styles/fonts/x.woff2":  licenseCore,
		"deploy/helm/probectl/a.yaml":   licenseCore,
		"internal/ebpf/l4flow_bpfel.go": licenseCore,
	} {
		if got := treeLicense(path); got != want {
			t.Errorf("treeLicense(%q) = %q, want %q", path, got, want)
		}
	}
}

func TestJoinLicenses(t *testing.T) {
	for _, tc := range []struct {
		in   []string
		want string
	}{
		{[]string{licenseCore}, "BUSL-1.1"},
		{[]string{licenseCommercial, licenseCore}, "BUSL-1.1 AND LicenseRef-Probectl-Commercial"},
		{[]string{"Apache-2.0", licenseCommercial, licenseClient, licenseCore}, "BUSL-1.1 AND MPL-2.0 AND LicenseRef-Probectl-Commercial AND Apache-2.0"},
		{[]string{"GPL-2.0-only OR BSD-3-Clause", "Apache-2.0", licenseCore}, "BUSL-1.1 AND Apache-2.0 AND (GPL-2.0-only OR BSD-3-Clause)"},
		{[]string{"GPL-2.0-only OR BSD-3-Clause"}, "GPL-2.0-only OR BSD-3-Clause"},
	} {
		counts := map[string]int{}
		for _, e := range tc.in {
			counts[e]++
		}
		if got := joinLicenses(counts); got != tc.want {
			t.Errorf("joinLicenses(%v) = %q, want %q", tc.in, got, tc.want)
		}
	}
	if got := licenseIDs("BUSL-1.1 AND (GPL-2.0-only OR BSD-3-Clause) AND LicenseRef-Probectl-Commercial"); !reflect.DeepEqual(got,
		[]string{"BUSL-1.1", "GPL-2.0-only", "BSD-3-Clause", "LicenseRef-Probectl-Commercial"}) {
		t.Errorf("licenseIDs = %v", got)
	}
}

func TestFirstPartyModuleMatchesGoMod(t *testing.T) {
	got, err := readModulePath(filepath.Join("..", "..", "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	if got != firstPartyModule {
		t.Fatalf("go.mod declares module %q, firstPartyModule is %q", got, firstPartyModule)
	}
}

// fakeLinker returns a fixed file list for one artifact.
type fakeLinker struct {
	artifact string
	linked   []string
	calls    int
}

func (f *fakeLinker) files(_ context.Context, artifact string, _ io.Writer) ([]linkedFile, error) {
	f.calls++
	if artifact != f.artifact {
		return nil, os.ErrNotExist
	}
	out := make([]linkedFile, len(f.linked))
	for i, p := range f.linked {
		out[i] = linkedFile{rel: p}
	}
	return out, nil
}

// testTree is a checkout with go.mod, the commercial LICENSES/ text and a
// REUSE map, like the one the release job builds.
func testTree(t *testing.T, files map[string]string) *sourceTree {
	t.Helper()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte("module "+firstPartyModule+"\n\ngo 1.26\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "LICENSES"), 0o755); err != nil {
		t.Fatal(err)
	}
	text, err := os.ReadFile(filepath.Join("..", "..", "LICENSES", licenseCommercial+".txt"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "LICENSES", licenseCommercial+".txt"), text, 0o644); err != nil {
		t.Fatal(err)
	}
	m, err := json.Marshal(reuseMap{ReuseToolVersion: "6.2.0", Files: files})
	if err != nil {
		t.Fatal(err)
	}
	mapPath := filepath.Join(root, "reuse-map.json")
	if err := os.WriteFile(mapPath, m, 0o644); err != nil {
		t.Fatal(err)
	}
	src, err := newSourceTree(root, mapPath)
	if err != nil {
		t.Fatal(err)
	}
	return src
}

func packagesByID(t *testing.T, d *spdxDoc) map[string]map[string]any {
	t.Helper()
	out := map[string]map[string]any{}
	for _, raw := range d.packages {
		b, err := json.Marshal(raw)
		if err != nil {
			t.Fatal(err)
		}
		var p map[string]any
		if err := json.Unmarshal(b, &p); err != nil {
			t.Fatal(err)
		}
		out[p["SPDXID"].(string)] = p
	}
	return out
}

func TestAnnotateDeclaresFirstPartyAndNothingElse(t *testing.T) {
	raw, err := os.ReadFile(fixture)
	if err != nil {
		t.Fatal(err)
	}
	before, err := parseSBOM(raw)
	if err != nil {
		t.Fatal(err)
	}
	// Fail-before: syft's own output leaves the first-party package undeclared.
	if _, problems := check(before); len(problems) == 0 || !strings.Contains(strings.Join(problems, "\n"), `declares "NOASSERTION"`) {
		t.Fatalf("check passed syft's unannotated output: %v", problems)
	}

	src := testTree(t, map[string]string{
		"cmd/probectl-agent/main.go":      licenseCore,
		"ee/billing/billing.go":           licenseCommercial,
		"internal/gen/gnmi/gnmi.pb.go":    "Apache-2.0",
		"internal/ebpf/bpf/l4flow.bpf.c":  "GPL-2.0-only OR BSD-3-Clause",
		"internal/ebpf/loader.go":         licenseCore,
		"internal/webui/dist/index.html":  licenseCore,
		"web/src/styles/fonts/syne.woff2": "OFL-1.1", // not linked: must not appear
	})
	link := &fakeLinker{
		artifact: "/probectl-agent_v0.0.0-rehearsal_linux_arm64",
		linked: []string{
			"cmd/probectl-agent/main.go",
			"ee/billing/billing.go",
			"internal/gen/gnmi/gnmi.pb.go",
			"internal/ebpf/loader.go",
			"internal/ebpf/l4flow_bpfel.go",         // untracked bpf2go loader: tree license
			"internal/ebpf/l4flow_bpfel.o",          // untracked BPF object: its program's license
			"internal/webui/dist/assets/index-x.js", // untracked web bundle: tree license
			"internal/webui/dist/index.html",
		},
	}
	after, err := parseSBOM(raw)
	if err != nil {
		t.Fatal(err)
	}
	report, err := annotate(after, src, link)
	if err != nil {
		t.Fatal(err)
	}
	if len(report) == 0 || !strings.Contains(report[0], "3 untracked build output") {
		t.Errorf("report does not count the untracked build output: %v", report)
	}

	const want = "BUSL-1.1 AND LicenseRef-Probectl-Commercial AND Apache-2.0 AND (GPL-2.0-only OR BSD-3-Clause)"
	b, a := packagesByID(t, before), packagesByID(t, after)
	if len(a) != len(b) {
		t.Fatalf("annotate changed the package count: %d -> %d", len(b), len(a))
	}
	firstParty := 0
	for id, pb := range b {
		pa := a[id]
		if pb["name"] == firstPartyModule {
			firstParty++
			if pa["licenseDeclared"] != want {
				t.Errorf("%s licenseDeclared = %v, want %q", id, pa["licenseDeclared"], want)
			}
			if pa["licenseConcluded"] != noAssertion {
				t.Errorf("%s licenseConcluded = %v; a declaration must not invent a conclusion", id, pa["licenseConcluded"])
			}
			pa["licenseDeclared"] = pb["licenseDeclared"]
		}
		if !reflect.DeepEqual(pa, pb) {
			t.Errorf("annotate changed package %s beyond the first-party licenseDeclared:\nbefore %v\nafter  %v", id, pb, pa)
		}
	}
	if firstParty != 1 {
		t.Fatalf("fixture has %d first-party packages, want 1", firstParty)
	}

	out, err := after.marshal()
	if err != nil {
		t.Fatal(err)
	}
	reparsed, err := parseSBOM(out)
	if err != nil {
		t.Fatal(err)
	}
	if lines, problems := check(reparsed); len(problems) != 0 {
		t.Fatalf("check rejected the annotated SBOM: %v (%v)", problems, lines)
	}
	var doc struct {
		CreationInfo struct {
			Creators []string `json:"creators"`
		} `json:"creationInfo"`
		Extracted []extractedLicense `json:"hasExtractedLicensingInfos"`
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Extracted) != 1 || doc.Extracted[0].LicenseID != licenseCommercial ||
		!strings.HasPrefix(doc.Extracted[0].ExtractedText, "PROBECTL COMMERCIAL SOURCE LICENSE") {
		t.Errorf("hasExtractedLicensingInfos = %+v, want the LICENSES/%s.txt text", doc.Extracted, licenseCommercial)
	}
	if got := doc.CreationInfo.Creators; len(got) == 0 || got[len(got)-1] != toolCreator {
		t.Errorf("creators = %v, want %q appended", got, toolCreator)
	}

	// Idempotent: a second pass declares the same and adds nothing.
	if _, err := annotate(reparsed, src, link); err != nil {
		t.Fatal(err)
	}
	again, err := reparsed.marshal()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(again, out) {
		t.Error("a second annotate pass changed the document")
	}
}

func TestCheckRequiresDefinedLicenseRefs(t *testing.T) {
	raw, err := os.ReadFile(fixture)
	if err != nil {
		t.Fatal(err)
	}
	d, err := parseSBOM(raw)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range d.packages {
		if isFirstPartyGoAny(p) {
			setStr(p, "licenseDeclared", "BUSL-1.1 AND LicenseRef-Probectl-Commercial")
		}
	}
	_, problems := check(d)
	if len(problems) != 1 || !strings.Contains(problems[0], "does not define it") {
		t.Fatalf("check problems = %v, want one undefined-LicenseRef problem", problems)
	}
}

func TestCheckRequiresFirstPartyNpmLicense(t *testing.T) {
	doc := []byte(`{"spdxVersion":"SPDX-2.3","packages":[
	 {"name":"github.com/ctlplne/probectl","SPDXID":"a","licenseDeclared":"BUSL-1.1",
	  "externalRefs":[{"referenceType":"purl","referenceLocator":"pkg:golang/github.com/ctlplne/probectl@v0.7.0"}]},
	 {"name":"probectl-browser-worker","SPDXID":"b","licenseDeclared":"NOASSERTION",
	  "externalRefs":[{"referenceType":"purl","referenceLocator":"pkg:npm/probectl-browser-worker@0.1.0"}]},
	 {"name":"left-pad","SPDXID":"c","licenseDeclared":"NOASSERTION",
	  "externalRefs":[{"referenceType":"purl","referenceLocator":"pkg:npm/left-pad@1.3.0"}]}]}`)
	d, err := parseSBOM(doc)
	if err != nil {
		t.Fatal(err)
	}
	_, problems := check(d)
	if len(problems) != 1 || !strings.Contains(problems[0], "probectl-browser-worker") {
		t.Fatalf("check problems = %v, want exactly the undeclared first-party npm package", problems)
	}
}

func TestCheckRequiresAFirstPartyGoPackage(t *testing.T) {
	d, err := parseSBOM([]byte(`{"spdxVersion":"SPDX-2.3","packages":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, problems := check(d); len(problems) != 1 {
		t.Fatalf("check passed an SBOM with no probectl package: %v", problems)
	}
}

func TestAnnotateFailsClosed(t *testing.T) {
	raw, err := os.ReadFile(fixture)
	if err != nil {
		t.Fatal(err)
	}
	d, err := parseSBOM(raw)
	if err != nil {
		t.Fatal(err)
	}
	src := testTree(t, map[string]string{"cmd/probectl-agent/main.go": licenseCore})
	if _, err := annotate(d, src, &fakeLinker{artifact: "/elsewhere"}); err == nil {
		t.Fatal("annotate succeeded although the binary behind the package could not be read")
	}
	empty, err := parseSBOM([]byte(`{"spdxVersion":"SPDX-2.3","packages":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := annotate(empty, src, &fakeLinker{}); err == nil {
		t.Fatal("annotate succeeded on an SBOM with no first-party package")
	}
	if _, err := parseSBOM([]byte(`{"bomFormat":"CycloneDX"}`)); err == nil {
		t.Fatal("parseSBOM accepted a non-SPDX document")
	}
}

func TestBinaryPaths(t *testing.T) {
	raw, err := os.ReadFile(fixture)
	if err != nil {
		t.Fatal(err)
	}
	d, err := parseSBOM(raw)
	if err != nil {
		t.Fatal(err)
	}
	got, err := firstPartyBinaries(d, firstPartyModule)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"/probectl-agent_v0.0.0-rehearsal_linux_arm64"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("firstPartyBinaries = %v, want %v", got, want)
	}
	// The resolver keeps every path inside the artifacts directory.
	r := binaryResolver{dir: t.TempDir()}
	if _, err := r.files(context.Background(), "../../../etc/passwd", io.Discard); err == nil ||
		!strings.Contains(err.Error(), filepath.Join(r.dir, "etc", "passwd")) {
		t.Fatalf("resolver escaped the artifacts directory: %v", err)
	}
}

func TestReadBuildOfThisBinary(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	b, err := readBuild(exe)
	if err != nil {
		t.Fatal(err)
	}
	if b.mainModule != firstPartyModule || b.goos == "" || b.goarch == "" {
		t.Fatalf("readBuild = %+v", b)
	}
}

// TestListFilesSeparatesEditions runs the real `go list` over this checkout:
// the core-only control plane links no ee/ file, the ee/ build does, and an
// agent links no ee/ file at all.
func TestListFilesSeparatesEditions(t *testing.T) {
	if testing.Short() {
		t.Skip("runs go list over the module")
	}
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	src, err := newSourceTreeForTest(root)
	if err != nil {
		t.Fatal(err)
	}
	countEE := func(mainPkg, tags string) int {
		t.Helper()
		files, err := listFiles(context.Background(), src, build{
			mainPackage: firstPartyModule + "/" + mainPkg, mainModule: firstPartyModule,
			tags: tags, goos: "linux", goarch: "amd64", cgo: "0",
		}, io.Discard)
		if err != nil {
			t.Fatal(err)
		}
		n := 0
		for _, f := range files {
			if treeLicense(f.rel) == licenseCommercial {
				n++
			}
		}
		return n
	}
	if n := countEE("cmd/probectl-control", "probectl_core"); n != 0 {
		t.Errorf("core-only probectl-control links %d ee/ files", n)
	}
	if n := countEE("cmd/probectl-control", ""); n == 0 {
		t.Error("the ee/ probectl-control build links no ee/ file; the edition seam moved")
	}
	if n := countEE("cmd/probectl-agent", ""); n != 0 {
		t.Errorf("probectl-agent links %d ee/ files", n)
	}
	if _, err := listFiles(context.Background(), src, build{mainPackage: "example.com/x", mainModule: "example.com/x", goos: "linux", goarch: "amd64"}, io.Discard); err == nil {
		t.Error("listFiles accepted a binary from another module")
	}
}

func newSourceTreeForTest(root string) (*sourceTree, error) {
	abs, err := filepath.EvalSymlinks(root)
	if err != nil {
		return nil, err
	}
	return &sourceTree{root: abs, module: firstPartyModule, files: map[string]string{}}, nil
}

func TestRunUsage(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run(nil, &out, &errb); code != 2 || !strings.Contains(errb.String(), "usage:") {
		t.Fatalf("run() = %d, stderr %q", code, errb.String())
	}
	if code := run([]string{"annotate", "-sbom", fixture}, &out, &errb); code != 2 {
		t.Fatalf("annotate without -reuse-map/-artifacts = %d, want 2", code)
	}
	errb.Reset()
	if code := run([]string{"check", "-sbom", fixture}, &out, &errb); code != 1 || !strings.Contains(errb.String(), "NOASSERTION") {
		t.Fatalf("check on syft output = %d, stderr %q", code, errb.String())
	}
}
