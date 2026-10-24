// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package ebpf

import (
	"regexp"
	"strings"
	"testing"
)

// nonRootUnitCaps is the capability set TestLiveNonRootL4Attach (ING-23)
// grants its non-root child, in setpriv syntax. It must be exactly what the
// shipped systemd units grant — TestNonRootL4ProofMirrorsTheShippedUnits
// derives it from their AmbientCapabilities= line — so the live proof can
// never pass on more privilege than an operator's agent has.
const nonRootUnitCaps = "-all,+bpf,+perfmon"

// TestNonRootL4ProofMirrorsTheShippedUnits keeps the live non-root L4 proof
// honest without a kernel: both shipped units must still run the agent as a
// non-root User= with the same ambient and bounding capability set, and that
// set must be the one the live test grants.
func TestNonRootL4ProofMirrorsTheShippedUnits(t *testing.T) {
	ambientRe := regexp.MustCompile(`(?m)^AmbientCapabilities=(.+)$`)
	for _, rel := range []string{
		"deploy/agent/probectl-ebpf-agent.service",
		"deploy/packaging/systemd/probectl-ebpf-agent.service",
	} {
		unit := readDeployContractFile(t, rel)
		m := ambientRe.FindStringSubmatch(unit)
		if m == nil {
			t.Fatalf("%s: no AmbientCapabilities= line", rel)
		}
		caps := strings.Fields(m[1])
		setpriv := []string{"-all"}
		for _, c := range caps {
			setpriv = append(setpriv, "+"+strings.ToLower(strings.TrimPrefix(c, "CAP_")))
		}
		if got := strings.Join(setpriv, ","); got != nonRootUnitCaps {
			t.Errorf("%s grants %q (setpriv %q), but TestLiveNonRootL4Attach grants %q — keep the live proof equal to the unit", rel, m[1], got, nonRootUnitCaps)
		}
		if !strings.Contains(unit, "\nCapabilityBoundingSet="+m[1]+"\n") {
			t.Errorf("%s: CapabilityBoundingSet= must equal AmbientCapabilities= (%q)", rel, m[1])
		}
		if !regexp.MustCompile(`(?m)^NoNewPrivileges=(yes|true)$`).MatchString(unit) {
			t.Errorf("%s: NoNewPrivileges must stay on (the live proof runs with no_new_privs)", rel)
		}
		user := regexp.MustCompile(`(?m)^User=(\S+)$`).FindStringSubmatch(unit)
		if user == nil || user[1] == "root" || user[1] == "0" {
			t.Errorf("%s: the eBPF agent must run as a non-root User= (ING-23)", rel)
		}
	}
}
