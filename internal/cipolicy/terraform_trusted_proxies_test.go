// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package cipolicy

import (
	"strings"
	"testing"
)

// RTO-10 (addendum): a chart rendered behind the ingress refuses to come up
// without control.trustedProxies (AUTHZ-04). The Terraform module omitted it
// entirely, so `tofu apply` of the kubernetes example could not install the
// product (it failed on trustedProxies the moment the database.url schema
// blocker was lifted). Pin the wiring so it cannot regress: the module must
// expose trusted_proxies and render it as control.trustedProxies, and the
// getting-started example must supply a non-empty default and default to a
// single-replica size (medium/large additionally need durable backends, PLAT-02,
// and would not apply out of the box).
func TestTerraformModuleWiresTrustedProxies(t *testing.T) {
	t.Parallel()

	vars := readRepoFile(t, "deploy", "terraform", "modules", "probectl", "variables.tf")
	if !strings.Contains(vars, `variable "trusted_proxies"`) {
		t.Error("the probectl Terraform module must declare a trusted_proxies variable (AUTHZ-04/RTO-10)")
	}

	main := readRepoFile(t, "deploy", "terraform", "modules", "probectl", "main.tf")
	if !strings.Contains(main, "control.trustedProxies[") || !strings.Contains(main, "var.trusted_proxies") {
		t.Error("the module must render var.trusted_proxies as control.trustedProxies[i] in base_set (AUTHZ-04/RTO-10)")
	}

	exMain := readRepoFile(t, "deploy", "terraform", "examples", "kubernetes", "main.tf")
	if !strings.Contains(exMain, "trusted_proxies") {
		t.Error("the kubernetes example must pass trusted_proxies to the module (RTO-10)")
	}

	exVars := readRepoFile(t, "deploy", "terraform", "examples", "kubernetes", "variables.tf")
	// A non-empty default so `tofu apply` installs without a manual override, and
	// a single-replica default size so PLAT-02's durable-backend guard does not
	// block the getting-started path.
	if !strings.Contains(exVars, `variable "trusted_proxies"`) || !strings.Contains(exVars, `default     = ["10.244.0.0/16"]`) {
		t.Error("the kubernetes example must default trusted_proxies to a non-empty CIDR list so tofu apply installs out of the box (RTO-10)")
	}
	if !strings.Contains(exVars, `default     = "small"`) {
		t.Error(`the kubernetes example must default size to "small" (single replica); medium/large require durable backends and would not apply out of the box (PLAT-02/RTO-10)`)
	}
}
