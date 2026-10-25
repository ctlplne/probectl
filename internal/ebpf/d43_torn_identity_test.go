// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package ebpf

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/bus"
	"github.com/ctlplne/probectl/internal/crypto"
)

// tenantFlows is the recorded flow fixture restated for this agent's tenant
// and registered identity.
func tenantFlows(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile("testdata/flows.json")
	if err != nil {
		t.Fatal(err)
	}
	raw = bytes.ReplaceAll(raw, []byte("00000000-0000-0000-0000-000000000001"), []byte(d43Tenant))
	raw = bytes.ReplaceAll(raw, []byte("00000000-0000-0000-0000-000000000101"), []byte(r2Agent))
	return writeChannelFile(t, t.TempDir(), "flows.json", raw)
}

// countingBus counts what the agent publishes (the L4 flow plane).
type countingBus struct {
	bus.Bus
	n atomic.Int64
}

func (c *countingBus) Publish(ctx context.Context, topic string, key, value []byte) error {
	c.n.Add(1)
	return c.Bus.Publish(ctx, topic, key, value)
}

// tornIdentity writes the identity a torn rotation leaves behind: a valid
// certificate with a key that is not its own, or an empty key.
func tornIdentity(t *testing.T, st *rotationStack, dir, kind string) (certFile, keyFile string) {
	t.Helper()
	certFile, keyFile = st.issue(t, dir, r2Agent)
	switch kind {
	case "mismatched key":
		_, other, err := crypto.CreateCSR("other")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(keyFile, other, 0o600); err != nil {
			t.Fatal(err)
		}
	case "zero-length key":
		if err := os.WriteFile(keyFile, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return certFile, keyFile
}

// R3 (DPR-396): an identity the channel cannot load refuses consented L7
// capture — logged, refused_channel, the gauge set — and never fails the
// agent: the L4 flow plane does not depend on the policy channel.
func TestUnloadableChannelIdentityRefusesL7NotTheAgent(t *testing.T) {
	st := startRotationStack(t, time.Hour)
	for _, kind := range []string{"mismatched key", "zero-length key"} {
		t.Run(kind, func(t *testing.T) {
			certFile, keyFile := tornIdentity(t, st, filepath.Join(t.TempDir(), "identity"), kind)
			rec := recordLiveStarts(t)
			cfg := st.config(r2Agent, certFile, keyFile, "")
			cfg.FixturePath = tenantFlows(t)
			cfg.FlushInterval = 100 * time.Millisecond
			b := &countingBus{Bus: bus.NewMemory()}
			a, err := New(cfg, b, slog.New(slog.NewTextHandler(io.Discard, nil)))
			if err != nil {
				t.Fatalf("the agent failed on an unloadable channel identity: %v", err)
			}
			if len(rec.starts) != 0 || a.L7CaptureActive() || !a.L7CaptureChannelRefused() {
				t.Fatalf("capture without a loadable channel: starts=%v refused=%v", rec.starts, a.L7CaptureChannelRefused())
			}
			ctx, cancel := context.WithTimeout(context.Background(), 700*time.Millisecond)
			defer cancel()
			if err := a.Run(ctx); err != nil {
				t.Fatal(err)
			}
			if b.n.Load() == 0 {
				t.Fatal("the L4 flow plane published nothing")
			}
		})
	}
}
