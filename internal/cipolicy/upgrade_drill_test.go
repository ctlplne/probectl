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
