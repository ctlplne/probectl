// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInventoryOnlyChecksEvidenceBeforeStartingHostCapture(t *testing.T) {
	t.Setenv("PROBECTL_EBPF_TENANT_ID", "test-tenant")
	t.Setenv("PROBECTL_EBPF_AGENT_ID", "test-collector")
	t.Setenv("PROBECTL_EBPF_BUS_MODE", "memory")
	t.Setenv("PROBECTL_EBPF_L7_CAPTURE", "false")
	t.Setenv("PROBECTL_EBPF_CONTROL_PLANE_GRPC_ADDR", "")
	path := filepath.Join(t.TempDir(), "agent.yaml")
	const base = "apiVersion: probectl.io/ebpf-agent/v1\n"
	for _, tc := range []struct{ config, want string }{
		{base, "--inventory-only requires kubernetes_inventory configuration"},
		{base + `kubernetes_inventory:
  namespace: owned
  binding_id: 11111111-1111-4111-8111-111111111111
  api_server: https://127.0.0.1:443
  evidence_grpc_addr: 127.0.0.1:443
  evidence_cert_file: missing.pem
  evidence_key_file: missing.key
  evidence_ca_file: missing-ca.pem
`, "inventory evidence identity must name this Kubernetes tenant and collector"},
	} {
		if err := os.WriteFile(path, []byte(tc.config), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := run([]string{"--config", path, "--inventory-only"}); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("inventory-only preflight got %v, want %q", err, tc.want)
		}
	}
}
