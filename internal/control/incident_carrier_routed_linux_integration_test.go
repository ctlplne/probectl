// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration && linux

package control

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/path"
)

// Runs the actual control-plane tracer with the isolated lab egress. The
// shipping HTTP handler still validates the target and owns the path store.
func routedCarrierDiscoverer(t *testing.T, namespace string) Discoverer {
	t.Helper()
	dir := t.TempDir()
	return func(ctx context.Context, cfg path.Config) (*path.Path, error) {
		payload, err := json.Marshal(cfg)
		if err != nil {
			return nil, err
		}
		output := filepath.Join(dir, "path.json")
		cmd := exec.CommandContext(ctx, "ip", "netns", "exec", namespace, os.Args[0], "-test.run=^TestRoutedCarrierTraceProcess$")
		cmd.Env = append(os.Environ(), "PROBECTL_TEST_ROUTED_CARRIER_TRACE="+string(payload), "PROBECTL_TEST_ROUTED_CARRIER_OUTPUT="+output)
		if log, err := cmd.CombinedOutput(); err != nil {
			return nil, fmt.Errorf("the isolated control-plane trace failed: %w: %s", err, log)
		}
		payload, err = os.ReadFile(output)
		if err != nil {
			return nil, err
		}
		var observed path.Path
		return &observed, json.Unmarshal(payload, &observed)
	}
}

func TestRoutedCarrierTraceProcess(t *testing.T) {
	raw := os.Getenv("PROBECTL_TEST_ROUTED_CARRIER_TRACE")
	if raw == "" {
		return
	}
	var cfg path.Config
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		t.Fatal(err)
	}
	// The topology has at most two hops. Include two additional TTLs
	// for the fault case while keeping the live test bounded.
	cfg.MaxHops, cfg.PerHopTimeout = 4, 250*time.Millisecond
	observed, err := path.Run(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(observed)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(os.Getenv("PROBECTL_TEST_ROUTED_CARRIER_OUTPUT"), payload, 0600); err != nil {
		t.Fatal(err)
	}
}
