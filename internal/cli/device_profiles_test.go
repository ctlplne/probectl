// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCLIDeviceProfilesAreLocalAndCompiled(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runCLI([]string{"device", "profiles"}, func(string) string { return "" }, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, stderr.String())
	}
	for _, required := range []string{
		"minimal\tSNMP 5m\tgNMI 2m",
		"standard\tSNMP 1m\tgNMI 30s",
		"topology-rich\tSNMP 1m\tgNMI 30s",
		"LLDP neighbors",
	} {
		if !strings.Contains(stdout.String(), required) {
			t.Fatalf("profiles output missing %q:\n%s", required, stdout.String())
		}
	}
}

func TestCLIDeviceConfigPreviewExcludesTenantAndCredentials(t *testing.T) {
	path := filepath.Join(t.TempDir(), "device.yaml")
	if err := os.WriteFile(path, []byte(`
apiVersion: probectl.io/device-agent/v1
tenant_id: tenant-private
collection_profile: minimal
devices:
  - address: 192.0.2.10
    transport: snmpv3
    credential: secret-reference-name
`), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := runCLI(
		[]string{"device", "config-preview", "--config", path},
		func(string) string { return "" },
		&stdout,
		&stderr,
	)
	if code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, stderr.String())
	}
	for _, forbidden := range []string{"tenant-private", "secret-reference-name"} {
		if strings.Contains(stdout.String(), forbidden) {
			t.Fatalf("preview leaked %q:\n%s", forbidden, stdout.String())
		}
	}
	for _, required := range []string{`"profile": "minimal"`, `"cadence": "5m"`} {
		if !strings.Contains(stdout.String(), required) {
			t.Fatalf("preview missing %q:\n%s", required, stdout.String())
		}
	}
}
