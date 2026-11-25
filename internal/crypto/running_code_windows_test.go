// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package crypto

import (
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestRunningWindowsImageIdentityRejectsAnIdenticalCopy(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	payload, err := os.ReadFile(executable)
	if err != nil {
		t.Fatal(err)
	}
	want := "sha256:" + hex.EncodeToString(Hash(payload))
	if got, err := RunningCodeIdentity(); err != nil || got != want {
		t.Fatalf("running executable did not report its complete SHA-256: %q, %v", got, err)
	}

	// This is deliberately the same program and the same bytes. The OS must
	// prove that the open file backs this process before a digest can qualify.
	path := filepath.Join(t.TempDir(), "unmapped-copy.exe")
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := runningWindowsImageIdentity(path); got != "" || !errors.Is(err, ErrRunningCodeIdentityUnavailable) {
		t.Fatalf("an unrelated file with the same bytes supplied evidence: %q, %v", got, err)
	}
}
