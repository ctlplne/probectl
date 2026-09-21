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

	"github.com/ctlplne/probectl/internal/agent"
)

func TestPackagingSmokeUsesPortableSed(t *testing.T) {
	t.Parallel()

	scriptPath := filepath.Join("..", "..", "scripts", "packaging-smoke.sh")
	raw, err := os.ReadFile(scriptPath)
	if err != nil {
		t.Fatal(err)
	}
	script := string(raw)
	if strings.Contains(script, "\nsed -i ") {
		t.Fatal("packaging smoke uses non-portable in-place sed")
	}
	for _, required := range []string{
		`absolute_rendered="$work/nfpm.absolute.yaml"`,
		`> "$absolute_rendered"`,
		`mv "$absolute_rendered" "$rendered"`,
	} {
		if !strings.Contains(script, required) {
			t.Fatalf("packaging smoke is missing portable render contract %q", required)
		}
	}
}

// DPR-034: the packaged agent conffile must point at exactly the files
// `probectl-agent enroll` writes into the unit's state directory and at the
// gRPC listener without a scheme; a fresh package that disagrees with the
// enrollment receipt cannot start after the documented enrollment.
func TestPackagedAgentConffileMatchesEnrollment(t *testing.T) {
	conf := readRepoFile(t, "deploy", "packaging", "config", "agent.yaml")
	for _, want := range []string{
		"cert_file: /var/lib/probectl-agent/identity/" + agent.IdentityCertFile,
		"key_file: /var/lib/probectl-agent/identity/" + agent.IdentityKeyFile,
		"ca_file: /var/lib/probectl-agent/identity/" + agent.IdentityServerCAFile,
		`grpc_addr: "CONTROL-HOST:9443"`,
		"identity:",
		"server: https://CONTROL-HOST:8443",
	} {
		if !strings.Contains(conf, want) {
			t.Errorf("deploy/packaging/config/agent.yaml is missing %q (DPR-034)", want)
		}
	}
	if strings.Contains(conf, `grpc_addr: "https://`) {
		t.Error("grpc_addr must be host:port without a scheme; the agent dials gRPC over mTLS, not HTTPS (DPR-034)")
	}
	unit := readRepoFile(t, "deploy", "packaging", "systemd", "probectl-agent.service")
	if !strings.Contains(unit, "StateDirectory=probectl-agent") || !strings.Contains(unit, "ReadWritePaths=/var/lib/probectl-agent") {
		t.Error("the unit must keep /var/lib/probectl-agent writable: that is where enroll lands the identity (DPR-034)")
	}
}
