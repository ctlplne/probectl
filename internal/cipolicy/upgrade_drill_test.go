// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package cipolicy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestIsolatedUpgradeDrillDoesNotDefaultToSharedPort(t *testing.T) {
	t.Parallel()

	scriptPath := filepath.Join("..", "..", "scripts", "upgrade_rollback_drill.sh")
	raw, err := os.ReadFile(scriptPath)
	if err != nil {
		t.Fatal(err)
	}
	script := string(raw)
	if strings.Contains(script, `PROBECTL_UPGRADE_PROBE_PORT:-18443`) {
		t.Fatal("isolated upgrade drill still defaults to shared host port 18443")
	}
	for _, required := range []string{
		"select_probe_port()",
		`/dev/tcp/127.0.0.1/`,
		`PROBECTL_UPGRADE_PROBE_PORT:-`,
		`PROBECTL_HTTP_ADDR="127.0.0.1:${PORT}"`,
	} {
		if !strings.Contains(script, required) {
			t.Fatalf("upgrade drill is missing isolated-port contract %q", required)
		}
	}
}
