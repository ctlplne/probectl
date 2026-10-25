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

// R3 (DPR-395): the seed repairs a torn identity. The state directory holds a
// valid, NEWER certificate of the same identity beside a key that is not its
// own (or an empty one) — what a torn rotation leaves — and the seed must
// replace it, so the restarted agent's channel loads and consented capture
// starts.
func TestSeedRepairsATornIdentity(t *testing.T) {
	st := startRotationStack(t, time.Hour)
	for _, kind := range []string{"mismatched key", "zero-length key"} {
		t.Run(kind, func(t *testing.T) {
			seed := filepath.Join(t.TempDir(), "seed")
			st.issue(t, seed, r2Agent)
			st.mu.Lock()
			st.leafTTL = 2 * time.Hour // the torn certificate outlives the seed
			st.mu.Unlock()
			t.Cleanup(func() { st.mu.Lock(); st.leafTTL = time.Hour; st.mu.Unlock() })
			certFile, keyFile := tornIdentity(t, st, filepath.Join(t.TempDir(), "identity"), kind)
			rec := recordLiveStarts(t)
			a, err := New(st.config(r2Agent, certFile, keyFile, seed), bus.NewMemory(), slog.New(slog.NewTextHandler(io.Discard, nil)))
			if err != nil {
				t.Fatal(err)
			}
			if err := crypto.VerifyIdentityPair(certFile, keyFile); err != nil {
				t.Fatalf("the torn identity was kept: %v", err)
			}
			if len(rec.starts) != 1 || !a.L7CaptureActive() {
				t.Fatalf("the repaired identity did not start consented capture: starts=%v", rec.starts)
			}
		})
	}
}

// R3 (DPR-397): a rotation that fails part-way never tears the pair. Here the
// certificate's write is made to fail (a full disk, a kill): the identity
// on disk must still load — the old pair or the new one, as a unit.
func TestRotationFailurePartWayKeepsALoadablePair(t *testing.T) {
	st := startRotationStack(t, time.Hour)
	dir := filepath.Join(t.TempDir(), "identity")
	certFile, keyFile := st.issue(t, dir, r2Agent)
	r, err := newIdentityRotator(st.config(r2Agent, certFile, keyFile, "").ControlPlane, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	// Block the certificate's replacement where a write-then-rename would put
	// its temporary file; an install that replaces the pair as one unit is
	// unaffected or fails before touching the pair.
	if err := os.Mkdir(certFile+".tmp", 0o700); err != nil {
		t.Fatal(err)
	}
	r.now = func() time.Time { return time.Now().Add(50 * time.Minute) }
	_, _ = r.check(context.Background())
	if err := crypto.VerifyIdentityPair(certFile, keyFile); err != nil {
		t.Fatalf("a rotation that failed part-way left a torn identity: %v", err)
	}
	// And a successful rotation lands the reply's CA bundle beside the pair.
	if rotated, err := r.check(context.Background()); err != nil || !rotated {
		t.Fatalf("rotation: %v %v", rotated, err)
	}
	if b, err := os.ReadFile(filepath.Join(dir, identityCABundleFile)); err != nil || !bytes.Contains(b, []byte("BEGIN CERTIFICATE")) {
		t.Fatalf("the rotation reply's CA bundle was not kept: %v", err)
	}
	if fi, err := os.Lstat(certFile); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Fatal("the certificate is not part of a versioned unit")
	}
}
