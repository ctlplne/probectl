// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package audit

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// DPR-011: a fresh deployment has no tenant keys yet. The keyring directory is
// created owner-only, an unset or relative path is refused with the setting
// named, and a tenant without a key still fails closed on wrap.
func TestLocalIRPublicKeyResolverCreatesMissingKeyringAndNamesTheSetting(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ir-keys")
	r, err := NewLocalIRPublicKeyResolver(dir)
	if err != nil {
		t.Fatalf("absent keyring directory must be created: %v", err)
	}
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		t.Fatalf("keyring directory not created: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o700 {
		t.Fatalf("keyring directory mode = %o, want 0700", perm)
	}
	if _, err := r.WrapProviderForTenant(context.Background(), "11111111-1111-4111-8111-111111111111"); !errors.Is(err, ErrIRKeyUnavailable) {
		t.Fatalf("empty keyring must fail closed with ErrIRKeyUnavailable, got %v", err)
	}
	for _, bad := range []string{"", "   ", "relative/ir-keys", "."} {
		_, err := NewLocalIRPublicKeyResolver(bad)
		if err == nil {
			t.Fatalf("path %q must be refused", bad)
		}
		if !strings.Contains(err.Error(), "PROBECTL_IR_PUBLIC_KEY_DIR") {
			t.Fatalf("refusal for %q must name the setting, got: %v", bad, err)
		}
	}
	file := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewLocalIRPublicKeyResolver(file); err == nil {
		t.Fatal("a regular file must be refused as a keyring directory")
	}
}
