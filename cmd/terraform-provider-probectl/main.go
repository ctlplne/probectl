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
	"os"

	"github.com/hashicorp/terraform-plugin-sdk/v2/plugin"

	"github.com/imfeelingtheagi/probectl/internal/crypto"
	"github.com/imfeelingtheagi/probectl/internal/terraformprovider"
)

func main() {
	if err := crypto.RunPowerOnSelfTest(nil); err != nil {
		fmt.Fprintln(os.Stderr, "terraform-provider-probectl:", err)
		os.Exit(1)
	}
	plugin.Serve(&plugin.ServeOpts{ProviderFunc: terraformprovider.New})
}
