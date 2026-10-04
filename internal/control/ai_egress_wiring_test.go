// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/ctlplne/probectl/internal/config"
	"github.com/ctlplne/probectl/internal/logging"
	"github.com/ctlplne/probectl/internal/store/pathstore"
)

// TestAIEgressSingleConstructionSite is a deliberate architecture lint, NOT a
// behavioral test: it asserts the control package builds the AI egress gate in
// exactly one place (AIRCA-001/005). Behavior cannot observe "no second
// construction site exists somewhere else in the package", so this guard has
// independent value. The wiring itself — Server.New storing THE gate and
// NewMCPServer refusing to run without it — is proven behaviorally below, so a
// pure rename/reformat of either call site does not break those.
func TestAIEgressSingleConstructionSite(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	dir := filepath.Dir(file)

	constructions := 0
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		constructions += strings.Count(string(b), "ai.NewEgressGate(")
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if constructions != 1 {
		t.Fatalf("control package must have exactly one production ai.NewEgressGate construction site, got %d", constructions)
	}
}

// TestServerStoresSharedAIEgressGate exercises the real wiring: Server.New must
// construct and store THE shared gate, reachable through the accessor the rest
// of the server uses. A nil pool is fine — existing unit tests build the server
// this way (authlimit_test.go) — so no DB is needed.
func TestServerStoresSharedAIEgressGate(t *testing.T) {
	s := New(&config.Config{}, logging.New(io.Discard, "error", "json"), nil, nil, nil, nil)
	if s.AIEgressGate() == nil {
		t.Fatal("Server.New must construct and store THE shared AI egress gate (AIRCA-001/005)")
	}
}

// TestNewMCPServerRequiresTheSharedGate proves NewMCPServer RECEIVES the shared
// gate rather than fabricating its own: passed a nil gate it panics immediately,
// before it touches the pool. This catches both real regressions — deleting the
// nil guard, and making the constructor build its own gate and ignore the
// argument — because in either case no panic fires on nil input.
func TestNewMCPServerRequiresTheSharedGate(t *testing.T) {
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("NewMCPServer must panic when passed a nil gate: it must RECEIVE the shared gate, not fabricate one")
		}
		if !strings.Contains(fmt.Sprint(r), "shared AI egress gate") {
			t.Fatalf("panic must name the shared-gate requirement, got: %v", r)
		}
	}()
	// nil aiGate (6th arg); the guard fires before pool/remed/gate are used.
	_ = NewMCPServer(&config.Config{}, logging.New(io.Discard, "error", "json"),
		nil, pathstore.NewMemory(), 120, nil, nil, nil)
}
