// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Command probectl-completeness validates capabilities.yaml against the
// independent denominator, canonical release catalog, exclusion policy, and
// actual binary/API/CLI/UI/docs/proof surfaces. It is a deterministic offline
// release gate and can emit HTML and JSON ledgers.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/ctlplne/probectl/internal/completeness"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	flags := flag.NewFlagSet("probectl-completeness", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	repoRoot := flags.String("repo-root", ".", "repository root")
	registryPath := flags.String("registry", "capabilities.yaml", "capability registry path, relative to repo root")
	jsonPath := flags.String("ledger-json", "", "write the machine-readable ledger to this path")
	htmlPath := flags.String("ledger-html", "", "write the self-contained HTML ledger to this path")
	selftest := flags.Bool("selftest", false, "plant missing-cell and none-by-design mutations and verify both directions")
	requireComplete := flags.Bool("require-complete", false, "fail when any acknowledged evidence gap remains")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *selftest && (*requireComplete || *jsonPath != "" || *htmlPath != "") {
		fmt.Fprintln(os.Stderr, "completeness: -selftest cannot be combined with -require-complete or ledger output")
		return 2
	}
	validator, err := completeness.NewValidator(*repoRoot)
	if err != nil {
		fmt.Fprintln(os.Stderr, "completeness:", err)
		return 2
	}
	registryFile := *registryPath
	if !filepath.IsAbs(registryFile) {
		registryFile = filepath.Join(*repoRoot, registryFile)
	}
	registry, err := completeness.LoadRegistry(registryFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "completeness:", err)
		return 2
	}
	if *selftest {
		if err := runSelftest(validator, registry); err != nil {
			fmt.Fprintln(os.Stderr, "completeness selftest:", err)
			return 1
		}
		fmt.Println("completeness self-test: OK (missing and unapproved CLI cells rejected; governed none-by-design cells accepted)")
		return 0
	}
	violations := validator.Validate(registry)
	if len(violations) > 0 {
		fmt.Fprintf(os.Stderr, "completeness: %d violation(s):\n", len(violations))
		for _, violation := range violations {
			location := violation.Capability
			if violation.Cell != "" {
				location += "." + violation.Cell
			}
			location = strings.TrimPrefix(location, ".")
			fmt.Fprintf(os.Stderr, "  - %s [%s]: %s\n", location, violation.Code, violation.Problem)
		}
		return 1
	}
	ledger := completeness.NewLedger(filepath.ToSlash(*registryPath), registry)
	if err := completeness.WriteJSON(*jsonPath, ledger); err != nil {
		fmt.Fprintln(os.Stderr, "completeness:", err)
		return 2
	}
	if err := completeness.WriteHTML(*htmlPath, ledger); err != nil {
		fmt.Fprintln(os.Stderr, "completeness:", err)
		return 2
	}
	if *requireComplete && ledger.Summary.GapCells > 0 {
		fmt.Fprintf(os.Stderr, "completeness-gate: incomplete (%d acknowledged gap(s); %d/%d spine cells covered)\n",
			ledger.Summary.GapCells,
			ledger.Summary.WiredCells+ledger.Summary.NoneByDesignCells,
			ledger.Summary.TotalCells,
		)
		return 1
	}
	result := "OK"
	if ledger.Summary.GapCells > 0 {
		result = "VALID, INCOMPLETE"
	}
	fmt.Printf("completeness-gate: %s (%d capabilities, %d/%d spine cells covered; %d acknowledged gap(s); HTML+JSON ledger rendered)\n",
		result,
		ledger.Summary.Capabilities,
		ledger.Summary.WiredCells+ledger.Summary.NoneByDesignCells,
		ledger.Summary.TotalCells,
		ledger.Summary.GapCells,
	)
	return 0
}

func runSelftest(validator *completeness.Validator, registry completeness.Registry) error {
	baseline := validator.Validate(registry)
	if len(baseline) != 0 {
		return fmt.Errorf("baseline registry has %d violation(s); selftest requires a green baseline", len(baseline))
	}
	index := -1
	for i, capability := range registry.Capabilities {
		if len(capability.CLI.Refs) > 0 {
			index = i
			break
		}
	}
	if index < 0 {
		return fmt.Errorf("baseline registry has no wired CLI cell to mutate")
	}
	planted := registry
	planted.Capabilities = append([]completeness.Capability(nil), registry.Capabilities...)
	planted.Capabilities[index].CLI = completeness.Cell{}
	missing := validator.Validate(planted)
	if !hasViolation(missing, planted.Capabilities[index].ID, "cli", "missing-cell") {
		return fmt.Errorf("planted missing CLI cell was not rejected")
	}
	planted.Capabilities[index].CLI = completeness.Cell{
		NoneByDesign: "Self-test-only deliberate absence with an explicit operator-facing rationale.",
	}
	unapproved := validator.Validate(planted)
	if !hasViolation(unapproved, planted.Capabilities[index].ID, "cli", "unapproved-none-by-design") {
		return fmt.Errorf("planted unapproved none-by-design CLI cell was not rejected")
	}
	for _, capability := range registry.Capabilities {
		for _, cell := range capability.NamedCells() {
			if strings.TrimSpace(cell.Cell.NoneByDesign) != "" {
				return nil
			}
		}
	}
	return fmt.Errorf("baseline registry has no governed none-by-design cell to verify")
}

func hasViolation(violations []completeness.Violation, capability, cell, code string) bool {
	for _, violation := range violations {
		if violation.Capability == capability && violation.Cell == cell && violation.Code == code {
			return true
		}
	}
	return false
}
