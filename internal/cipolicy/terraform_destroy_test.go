// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package cipolicy

import (
	"regexp"
	"strings"
	"testing"
)

// TestTerraformModuleDestroysProbectlResources closes RTO-11: the
// probectl-resources module created resources via a create-time local-exec but
// had NO destroy-time provisioner, so `terraform destroy` tore down only the
// Terraform state and left every test/alert/SLO/etc. live on the control plane.
// The fix captures the API-returned id at create time and DELETEs it on destroy.
//
// This is the committed guard for that wiring (the behavior itself was proven
// with a real `terraform apply && terraform destroy` against a stub probectl:
// create -> POST, destroy -> DELETE /v1/tests/<id>; the pre-fix module issued no
// DELETE). Fail-before: the original main.tf has no `when = destroy` provisioner.
func TestTerraformModuleDestroysProbectlResources(t *testing.T) {
	tf := readRepoFile(t, "deploy", "terraform", "modules", "probectl-resources", "main.tf")

	// A destroy-time provisioner must exist.
	if !regexp.MustCompile(`when\s*=\s*destroy`).MatchString(tf) {
		t.Fatal("RTO-11: the module has no `when = destroy` provisioner, so `terraform destroy` leaks probectl resources on the server")
	}
	// It must issue a DELETE against the created resource's path/id.
	if !strings.Contains(tf, `api DELETE "$PROBECTL_PATH/$ID"`) {
		t.Error("RTO-11: the destroy provisioner must `probectl api DELETE \"$PROBECTL_PATH/$ID\"` the resource it created")
	}
	// The create provisioner must capture the server id so destroy has a target.
	if !strings.Contains(tf, `"$PROBECTL_ID_FILE"`) {
		t.Error("RTO-11: the create provisioner must capture the created resource id into PROBECTL_ID_FILE for destroy")
	}
	// A destroy provisioner may reference only self; the delete must read
	// url/tenant/path from self.input, not var.* (which terraform rejects).
	if !strings.Contains(tf, "self.input.path") || !strings.Contains(tf, "self.input.api_url") {
		t.Error("RTO-11: the destroy provisioner must source url/path from self.input (var.* is invalid in a destroy provisioner)")
	}
}
