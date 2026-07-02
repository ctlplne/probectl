// SPDX-License-Identifier: LicenseRef-probectl-TBD

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
