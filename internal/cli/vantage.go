// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const vantageUsage = "probectl vantage deploy --dir <terraform-root> [--apply]"

func cmdVantage(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] == "--help" || args[0] == "-h" || args[0] == "help" {
		fmt.Fprintln(stdout, vantageUsage)
		return 0
	}
	if args[0] != "deploy" {
		fmt.Fprintln(stderr, vantageUsage)
		return 2
	}
	if len(args) == 2 && (args[1] == "--help" || args[1] == "-h") {
		fmt.Fprintln(stdout, vantageUsage)
		fmt.Fprintln(stdout, "Initialize the selected cloud deployment and print its plan. Use --apply to confirm and deploy through Terraform or OpenTofu.")
		return 0
	}

	flags := flag.NewFlagSet("vantage deploy", flag.ContinueOnError)
	flags.SetOutput(stderr)
	directory := flags.String("dir", "", "directory with the tenant's Terraform deployment")
	apply := flags.Bool("apply", false, "confirm and deploy the selected infrastructure plan")
	if err := flags.Parse(args[1:]); err != nil {
		return 2
	}
	if *directory == "" || flags.NArg() != 0 {
		fmt.Fprintln(stderr, vantageUsage)
		return 2
	}
	root, err := filepath.Abs(*directory)
	if err != nil {
		fmt.Fprintln(stderr, "vantage deploy requires a valid Terraform root directory")
		return 2
	}
	if info, err := os.Stat(root); err != nil || !info.IsDir() {
		fmt.Fprintln(stderr, "vantage deploy requires an existing Terraform root directory")
		return 2
	}
	executable, err := exec.LookPath("terraform")
	if errors.Is(err, exec.ErrNotFound) {
		executable, err = exec.LookPath("tofu")
	}
	if err != nil {
		fmt.Fprintln(stderr, "vantage deploy requires Terraform or OpenTofu on PATH")
		return 1
	}
	if err := runVantageTerraform(executable, root, "init", "-input=false", stdin, stdout, stderr); err != nil {
		fmt.Fprintln(stderr, "vantage deployment initialization failed")
		return 1
	}
	operation, input := "plan", "-input=false"
	if *apply {
		operation, input = "apply", "-input=true"
	}
	if err := runVantageTerraform(executable, root, operation, input, stdin, stdout, stderr); err != nil {
		fmt.Fprintln(stderr, "vantage deployment did not complete")
		return 1
	}
	return 0
}

func runVantageTerraform(executable, root, operation, input string, stdin io.Reader, stdout, stderr io.Writer) error {
	command := exec.Command(executable, "-chdir="+root, operation, input)
	command.Stdin, command.Stdout, command.Stderr = stdin, stdout, stderr
	environment := command.Environ()
	command.Env = make([]string, 0, len(environment))
	for _, variable := range environment {
		name, _, _ := strings.Cut(variable, "=")
		if strings.HasPrefix(strings.ToUpper(name), "PROBECTL_") {
			continue
		}
		command.Env = append(command.Env, variable)
	}
	return command.Run()
}
