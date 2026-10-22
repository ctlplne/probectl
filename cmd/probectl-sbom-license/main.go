// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

// probectl-sbom-license declares the real license of probectl's own code in a
// syft-generated SPDX SBOM (G3, decision D-58).
//
// syft reads a Go binary's build information, which names the first-party
// main module (github.com/ctlplne/probectl) but carries no license, so syft
// writes licenseDeclared NOASSERTION for it. This tool fills in exactly that
// field, and only for first-party Go packages:
//
//  1. It opens the binary the package came from (syft's sourceInfo names it,
//     relative to the scanned directory) and reads the build information the
//     Go linker embedded: the main package, -tags, GOOS, GOARCH, CGO_ENABLED.
//  2. It asks `go list -deps` for every first-party file compiled into that
//     binary under those settings, from the same source checkout.
//  3. It looks each file up in the per-file license map that
//     scripts/check_reuse_licensing.sh writes from the pinned `reuse lint`
//     (REUSE_MAP_OUT), so REUSE.toml stays the single source of truth. A file
//     the map does not know is build output that git does not track (the web
//     bundle, generated BPF loaders); it takes its tree's license, as LICENSE
//     says every untagged file does.
//  4. The distinct licenses, joined with AND, become licenseDeclared: a core
//     agent is BUSL-1.1; the ee/ control plane adds
//     LicenseRef-Probectl-Commercial; a binary that links the vendored gNMI
//     code adds Apache-2.0. A LicenseRef used this way is defined in
//     hasExtractedLicensingInfos with its LICENSES/ text, as SPDX requires.
//
// Every other package, including every third-party license syft detected, is
// left exactly as syft wrote it. licenseConcluded stays NOASSERTION: this is a
// declaration by the authors, not a reviewer's conclusion.
//
// Usage:
//
//	probectl-sbom-license annotate -sbom <spdx.json> -reuse-map <map.json> -artifacts <dir> [-root <repo>] [-o <out>]
//	probectl-sbom-license check    -sbom <spdx.json>
//	probectl-sbom-license binaries -sbom <spdx.json>
//
// check fails when a first-party package (the Go main module, or an npm/PyPI
// package named probectl-*) still declares NOASSERTION, or when the document
// uses a LicenseRef it does not define. binaries prints the artifact path of
// each first-party Go package, so a release job can copy those binaries out of
// an image before annotating the image's SBOM.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)
		return 2
	}
	switch args[0] {
	case "annotate":
		return runAnnotate(args[1:], stdout, stderr)
	case "check":
		return runCheck(args[1:], stdout, stderr)
	case "binaries":
		return runBinaries(args[1:], stdout, stderr)
	default:
		usage(stderr)
		return 2
	}
}

func usage(w io.Writer) {
	fmt.Fprintln(w, `usage:
  probectl-sbom-license annotate -sbom <spdx.json> -reuse-map <map.json> -artifacts <dir> [-root <repo>] [-o <out>]
  probectl-sbom-license check    -sbom <spdx.json>
  probectl-sbom-license binaries -sbom <spdx.json>`)
}

func runAnnotate(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("annotate", flag.ContinueOnError)
	fs.SetOutput(stderr)
	sbomPath := fs.String("sbom", "", "syft SPDX JSON SBOM to annotate")
	mapPath := fs.String("reuse-map", "", "per-file license map from scripts/check_reuse_licensing.sh (REUSE_MAP_OUT)")
	artifacts := fs.String("artifacts", "", "directory syft scanned (the binaries named by each package's sourceInfo)")
	root := fs.String("root", ".", "source checkout the binaries were built from")
	out := fs.String("o", "", "output path (default: rewrite -sbom in place)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *sbomPath == "" || *mapPath == "" || *artifacts == "" || fs.NArg() != 0 {
		usage(stderr)
		return 2
	}
	if *out == "" {
		*out = *sbomPath
	}
	src, err := newSourceTree(*root, *mapPath)
	if err != nil {
		fmt.Fprintf(stderr, "probectl-sbom-license: %v\n", err)
		return 1
	}
	doc, err := readSBOM(*sbomPath)
	if err != nil {
		fmt.Fprintf(stderr, "probectl-sbom-license: %v\n", err)
		return 1
	}
	report, err := annotate(doc, src, binaryResolver{dir: *artifacts, src: src})
	if err != nil {
		fmt.Fprintf(stderr, "probectl-sbom-license: %v\n", err)
		return 1
	}
	if err := writeSBOM(*out, doc); err != nil {
		fmt.Fprintf(stderr, "probectl-sbom-license: %v\n", err)
		return 1
	}
	for _, line := range report {
		fmt.Fprintln(stdout, line)
	}
	return 0
}

func runCheck(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	fs.SetOutput(stderr)
	sbomPath := fs.String("sbom", "", "SPDX JSON SBOM to check")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *sbomPath == "" || fs.NArg() != 0 {
		usage(stderr)
		return 2
	}
	doc, err := readSBOM(*sbomPath)
	if err != nil {
		fmt.Fprintf(stderr, "probectl-sbom-license: %v\n", err)
		return 1
	}
	lines, problems := check(doc)
	for _, line := range lines {
		fmt.Fprintln(stdout, line)
	}
	if len(problems) > 0 {
		for _, p := range problems {
			fmt.Fprintf(stderr, "::error::probectl-sbom-license: %s: %s\n", *sbomPath, p)
		}
		return 1
	}
	return 0
}

func runBinaries(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("binaries", flag.ContinueOnError)
	fs.SetOutput(stderr)
	sbomPath := fs.String("sbom", "", "syft SPDX JSON SBOM")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *sbomPath == "" || fs.NArg() != 0 {
		usage(stderr)
		return 2
	}
	doc, err := readSBOM(*sbomPath)
	if err != nil {
		fmt.Fprintf(stderr, "probectl-sbom-license: %v\n", err)
		return 1
	}
	paths, err := firstPartyBinaries(doc, firstPartyModule)
	if err != nil {
		fmt.Fprintf(stderr, "probectl-sbom-license: %v\n", err)
		return 1
	}
	for _, p := range paths {
		fmt.Fprintln(stdout, p)
	}
	return 0
}
