// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package main

import (
	"testing"

	"github.com/ctlplne/probectl/internal/config"
)

// G9: backup-control-state seals the test-bundle signing key FILE serve uses;
// when the key is secret-injected (it wins in serve) the file is not the live
// key and is not captured — the restored host re-injects the same secret.
func TestBackupControlStateCapturesTheLiveTestSyncKey(t *testing.T) {
	if got := testSyncKeyFileToCapture(&config.Config{TestSyncSigningKeyFile: "/var/lib/probectl/ts.pem"}); got != "/var/lib/probectl/ts.pem" {
		t.Fatalf("file-backed deployment captures %q, want its key file", got)
	}
	if got := testSyncKeyFileToCapture(&config.Config{TestSyncSigningKey: "aW5saW5l", TestSyncSigningKeyFile: "/var/lib/probectl/ts.pem"}); got != "" {
		t.Fatalf("secret-injected deployment captures %q, want nothing", got)
	}
}
