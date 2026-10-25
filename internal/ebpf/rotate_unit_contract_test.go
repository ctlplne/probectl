// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package ebpf

import (
	"path"
	"regexp"
	"strings"
	"testing"
)

// D-43 R2: the agent rotates its channel certificate by rewriting the
// control_plane cert/key files, so under each shipped unit (ProtectSystem=strict:
// read-only except ReadWritePaths= and StateDirectory=) the identity directory
// its example config names must be writable — and the example config must name
// the rotation endpoint.
func TestShippedUnitsLetTheAgentRotateItsIdentity(t *testing.T) {
	for _, pair := range []struct{ unit, config string }{
		{"deploy/agent/probectl-ebpf-agent.service", "deploy/agent/probectl-ebpf-agent.example.yml"},
		{"deploy/packaging/systemd/probectl-ebpf-agent.service", "deploy/packaging/config/ebpf-agent.yaml"},
	} {
		unit, cfg := readDeployContractFile(t, pair.unit), readDeployContractFile(t, pair.config)
		var writable []string
		for _, line := range strings.Split(unit, "\n") {
			switch {
			case strings.HasPrefix(line, "ReadWritePaths="):
				for _, p := range strings.Fields(strings.TrimPrefix(line, "ReadWritePaths=")) {
					writable = append(writable, strings.TrimPrefix(p, "-"))
				}
			case strings.HasPrefix(line, "StateDirectory="):
				for _, d := range strings.Fields(strings.TrimPrefix(line, "StateDirectory=")) {
					writable = append(writable, "/var/lib/"+d)
				}
			}
		}
		if !strings.Contains(unit, "\nProtectSystem=strict\n") {
			t.Errorf("%s: ProtectSystem=strict expected (this check reasons about it)", pair.unit)
		}
		if !regexp.MustCompile(`(?m)^#\s+rotate_url:\s+https://\S+`).MatchString(cfg) {
			t.Errorf("%s: the control_plane example names no https rotate_url", pair.config)
		}
		for _, key := range []string{"cert_file", "key_file"} {
			m := regexp.MustCompile(`(?m)^#\s+` + key + `:\s+(\S+)`).FindStringSubmatch(cfg)
			if m == nil {
				t.Fatalf("%s: no control_plane %s example", pair.config, key)
			}
			dir := path.Dir(m[1])
			ok := false
			for _, w := range writable {
				if dir == w || strings.HasPrefix(dir, strings.TrimSuffix(w, "/")+"/") {
					ok = true
				}
			}
			if !ok {
				t.Errorf("%s: %s %s is read-only under %s (writable: %v) — rotation cannot replace it", pair.config, key, m[1], pair.unit, writable)
			}
		}
	}
}
