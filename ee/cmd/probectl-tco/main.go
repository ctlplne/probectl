// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License; see ee/LICENSE.

// Command probectl-tco evaluates a local JSON worksheet. It intentionally has no
// network client and never reads runtime telemetry.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/ctlplne/probectl/ee/pricing"
)

func main() {
	input := flag.String("input", "", "path to a probectl-tco-input/v1 JSON file (required)")
	format := flag.String("format", "json", "output format: json or markdown")
	flag.Parse()
	if *input == "" {
		fatalf("-input is required")
	}
	f, err := os.Open(*input)
	if err != nil {
		fatalf("open input: %v", err)
	}
	defer f.Close()
	decoder := json.NewDecoder(io.LimitReader(f, 4<<20))
	decoder.DisallowUnknownFields()
	var model pricing.Model
	if err := decoder.Decode(&model); err != nil {
		fatalf("decode input: %v", err)
	}
	report, err := pricing.Calculate(model)
	if err != nil {
		fatalf("calculate: %v", err)
	}
	switch *format {
	case "json":
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(report); err != nil {
			fatalf("encode report: %v", err)
		}
	case "markdown":
		if _, err := io.WriteString(os.Stdout, pricing.RenderMarkdown(report)); err != nil {
			fatalf("write report: %v", err)
		}
	default:
		fatalf("unsupported -format %q", *format)
	}
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "probectl-tco: "+format+"\n", args...)
	os.Exit(2)
}
