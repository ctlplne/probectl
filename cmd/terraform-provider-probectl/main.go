// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Command terraform-provider-probectl is the native Terraform provider for
// customer/MSP-owned probectl control planes.
package main

import (
	"fmt"
	"io"
	"os"

	"github.com/hashicorp/terraform-plugin-sdk/v2/plugin"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/terraformprovider"
	"github.com/ctlplne/probectl/internal/version"
)

func main() {
	if writeVersion(os.Args, os.Stdout) {
		return
	}
	if err := crypto.RunPowerOnSelfTest(nil); err != nil {
		fmt.Fprintln(os.Stderr, "terraform-provider-probectl:", err)
		os.Exit(1)
	}
	plugin.Serve(&plugin.ServeOpts{ProviderFunc: terraformprovider.New})
}

func writeVersion(args []string, out io.Writer) bool {
	if len(args) != 2 {
		return false
	}
	switch args[1] {
	case "version", "-version", "--version":
		fmt.Fprintln(out, "terraform-provider-probectl", version.Get())
		return true
	default:
		return false
	}
}
