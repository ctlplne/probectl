// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package agent

import (
	"os"
	"strings"
	"testing"
)

// ING-29: the default store-and-forward buffer directory must sit under a path
// the packaged, hardened systemd unit can write. The unit makes the filesystem
// read-only except ReadWritePaths + StateDirectory, so a default outside those
// makes MkdirAll fail and the agent never starts. This reads the SHIPPED unit
// file and asserts the default is covered — it fails if either drifts.
func TestDefaultBufferDirIsWritableByPackagedUnit(t *testing.T) {
	const unitPath = "../../deploy/packaging/systemd/probectl-agent.service"
	raw, err := os.ReadFile(unitPath)
	if err != nil {
		t.Fatalf("read packaged unit %s: %v", unitPath, err)
	}

	var writable []string
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "ReadWritePaths="):
			writable = append(writable, strings.Fields(strings.TrimPrefix(line, "ReadWritePaths="))...)
		case strings.HasPrefix(line, "StateDirectory="):
			// systemd roots StateDirectory=foo at /var/lib/foo and makes it writable.
			for _, d := range strings.Fields(strings.TrimPrefix(line, "StateDirectory=")) {
				writable = append(writable, "/var/lib/"+d)
			}
		}
	}
	if len(writable) == 0 {
		t.Fatal("packaged unit declares no ReadWritePaths/StateDirectory")
	}

	covered := false
	for _, w := range writable {
		if DefaultBufferDir == w || strings.HasPrefix(DefaultBufferDir, strings.TrimRight(w, "/")+"/") {
			covered = true
			break
		}
	}
	if !covered {
		t.Fatalf("default buffer dir %q is not under any writable path of the packaged unit %v — the agent will fail to create its buffer (ING-29)", DefaultBufferDir, writable)
	}
}
