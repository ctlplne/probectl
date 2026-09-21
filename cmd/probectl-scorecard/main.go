// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

// Command probectl-scorecard produces an offline, evidence-aware comparison.
// Unknown evidence stays unknown and is never silently scored as zero.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/ctlplne/probectl/internal/bakeoff"
)

func main() {
	catalogPath := flag.String("catalog", "", "evidence catalog JSON path (required)")
	profilePath := flag.String("profile", "", "buyer profile JSON path (required)")
	format := flag.String("format", "markdown", "output format: markdown or json")
	flag.Parse()
	if *catalogPath == "" || *profilePath == "" {
		fatalf("-catalog and -profile are required")
	}
	var catalog bakeoff.Catalog
	readStrict(*catalogPath, &catalog)
	var profile bakeoff.Profile
	readStrict(*profilePath, &profile)
	report, err := bakeoff.Evaluate(catalog, profile)
	if err != nil {
		fatalf("evaluate: %v", err)
	}
	switch *format {
	case "markdown":
		if _, err := io.WriteString(os.Stdout, bakeoff.RenderMarkdown(report)); err != nil {
			fatalf("write: %v", err)
		}
	case "json":
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(report); err != nil {
			fatalf("encode: %v", err)
		}
	default:
		fatalf("unsupported -format %q", *format)
	}
}

func readStrict(path string, target any) {
	f, err := os.Open(path)
	if err != nil {
		fatalf("open %s: %v", path, err)
	}
	defer f.Close()
	decoder := json.NewDecoder(io.LimitReader(f, 4<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		fatalf("decode %s: %v", path, err)
	}
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "probectl-scorecard: "+format+"\n", args...)
	os.Exit(2)
}
