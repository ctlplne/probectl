// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package cipolicy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestDeliveryAuditToolIsRepositoryOnly keeps the independent auditor outside
// every customer artifact. It must inspect release bits from a separate trust
// domain; accidentally packaging it alongside those bits would blur the
// implementer/auditor boundary and expand the supported product surface.
func TestDeliveryAuditToolIsRepositoryOnly(t *testing.T) {
	const tool = "probectl-delivery-audit"
	if info, err := os.Stat(filepath.Join(repoRoot(t), "cmd", tool)); err != nil {
		t.Fatalf("repository-only audit command is missing: %v", err)
	} else if !info.IsDir() {
		t.Fatalf("cmd/%s is not a directory", tool)
	}

	for _, binary := range makefileBinaries(t) {
		if binary == tool {
			t.Fatalf("Makefile BINARIES includes repository-only %s", tool)
		}
	}

	// These are the independent shipping inventories. A literal tool name in
	// any one means a future edit tried to publish/package the auditor.
	for _, path := range []string{
		"scripts/build-release-binaries.sh",
		"scripts/airgap-bundle.sh",
		"scripts/check_airgap_bundle.sh",
		".github/workflows/release.yml",
	} {
		body := readRepoFile(t, strings.Split(path, "/")...)
		if strings.Contains(body, tool) {
			t.Errorf("%s includes repository-only %s", path, tool)
		}
	}
}
