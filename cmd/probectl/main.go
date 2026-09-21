// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

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

	"github.com/ctlplne/probectl/internal/cli"
	"github.com/ctlplne/probectl/internal/crypto"
)

func main() {
	if err := crypto.RunPowerOnSelfTest(nil); err != nil {
		fmt.Fprintln(os.Stderr, "probectl:", err)
		os.Exit(1)
	}
	os.Exit(cli.RunWithStdin(os.Args[1:], os.Getenv, os.Stdin, os.Stdout, os.Stderr))
}
