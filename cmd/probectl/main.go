// SPDX-License-Identifier: LicenseRef-probectl-TBD

// Command probectl is the probectl command-line interface for the control-plane
// /v1 API. It has typed commands for high-frequency workflows plus generated
// resource-oriented groups for the served tenant API surface; the parity gate in
// internal/cli fails when OpenAPI gains a /v1 operation without a CLI command or
// an explicit none-by-design exception. See `probectl help`.
//
// Configuration comes from flags or PROBECTL_API_URL / PROBECTL_API_TOKEN /
// PROBECTL_TENANT. The implementation lives in internal/cli (so it is testable).
package main

import (
	"fmt"
	"os"

	"github.com/imfeelingtheagi/probectl/internal/cli"
	"github.com/imfeelingtheagi/probectl/internal/crypto"
)

func main() {
	if err := crypto.RunPowerOnSelfTest(nil); err != nil {
		fmt.Fprintln(os.Stderr, "probectl:", err)
		os.Exit(1)
	}
	os.Exit(cli.Run(os.Args[1:], os.Getenv, os.Stdout, os.Stderr))
}
