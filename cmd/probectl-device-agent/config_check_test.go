// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestConfigCheckPrintsCredentialFreePreviewWithoutNetwork(t *testing.T) {
	path := filepath.Join(t.TempDir(), "device.yaml")
	if err := os.WriteFile(path, []byte(`
apiVersion: probectl.io/device-agent/v1
tenant_id: tenant-private
collection_profile: topology-rich
devices:
  - address: 192.0.2.10
    transport: snmpv3
    credential: secret-reference-name
`), 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := runConfigCheck([]string{"-config", path}, &out); err != nil {
		t.Fatalf("config-check: %v", err)
	}
	text := out.String()
	for _, required := range []string{
		`"profile": "topology-rich"`,
		`"address": "192.0.2.10"`,
		`"LLDP neighbors"`,
		`"network_requests_performed": false`,
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("preview missing %q:\n%s", required, text)
		}
	}
	for _, forbidden := range []string{"tenant-private", "secret-reference-name"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("preview leaked %q:\n%s", forbidden, text)
		}
	}
}

func TestConfigCheckFailsClosedBeforePreview(t *testing.T) {
	path := filepath.Join(t.TempDir(), "device.yaml")
	if err := os.WriteFile(path, []byte(`
apiVersion: probectl.io/device-agent/v1
tenant_id: tenant-private
collection_profile: downloaded-vendor-profile
devices:
  - address: 192.0.2.10
    transport: snmpv3
    credential: secret-reference-name
`), 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	err := runConfigCheck([]string{"-config", path}, &out)
	if err == nil || !strings.Contains(err.Error(), "unknown collection_profile") {
		t.Fatalf("error = %v", err)
	}
	if out.Len() != 0 {
		t.Fatalf("invalid config emitted preview: %s", out.String())
	}
}
