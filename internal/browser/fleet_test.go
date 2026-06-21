// SPDX-License-Identifier: LicenseRef-probectl-TBD

package browser

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/objectstore"
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
)

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// trivialScript is a minimal valid script for orchestration tests.
func trivialScript() Script {
	return Script{Name: "noop", StartURL: "http://x", Steps: []Step{{Action: Screenshot}}}
}

// --- fake drivers ---

// countingDriver tracks how many of its runs overlap (for the concurrency cap).
type countingDriver struct {
	cur  *int32
	peak *int32
	hold time.Duration
}

func (countingDriver) Name() string { return "counting" }
func (d countingDriver) Run(ctx context.Context, s Script) (RunOutput, error) {
	n := atomic.AddInt32(d.cur, 1)
	for {
		p := atomic.LoadInt32(d.peak)
		if n <= p || atomic.CompareAndSwapInt32(d.peak, p, n) {
			break
		}
	}
	select {
	case <-time.After(d.hold):
	case <-ctx.Done():
	}
	atomic.AddInt32(d.cur, -1)
	return RunOutput{Result: Result{Script: s.Name, Success: true}}, nil
}

// lifecycleDriver counts creations/closes and can sleep (ctx-respecting) or carry
// a screenshot.
type lifecycleDriver struct {
	closed     *int32
	sleep      time.Duration
	screenshot []byte
	fail       bool
}

func (lifecycleDriver) Name() string { return "lifecycle" }
func (d *lifecycleDriver) Run(ctx context.Context, s Script) (RunOutput, error) {
	if d.sleep > 0 {
		select {
		case <-time.After(d.sleep):
		case <-ctx.Done():
			return RunOutput{}, ctx.Err()
		}
	}
	return RunOutput{
		Result:         Result{Script: s.Name, Success: !d.fail, Error: errIf(d.fail)},
		Screenshot:     d.screenshot,
		ScreenshotType: "image/png",
	}, nil
}
func (d *lifecycleDriver) Close() error {
	if d.closed != nil {
		atomic.AddInt32(d.closed, 1)
	}
	return nil
}

func errIf(b bool) string {
	if b {
		return "transaction assertion failed"
	}
	return ""
}

// The pool size caps how many runs execute at once.
func TestFleetConcurrencyCap(t *testing.T) {
	var cur, peak int32
	factory := func() Driver { return countingDriver{cur: &cur, peak: &peak, hold: 30 * time.Millisecond} }
	fleet := NewFleet(Config{MaxConcurrency: 3, RunTimeout: time.Second}, factory, nil, quiet())
	defer fleet.Close()

	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _, _ = fleet.Run(context.Background(), "t1", trivialScript()) }()
	}
	wg.Wait()
	if p := atomic.LoadInt32(&peak); p > 3 {
		t.Fatalf("concurrency cap exceeded: peak %d > 3", p)
	}
}

// A worker is recycled after RecycleAfter runs (driver Closed + a fresh one built).
func TestFleetRecyclesWorkers(t *testing.T) {
	var created, closed int32
	factory := func() Driver { atomic.AddInt32(&created, 1); return &lifecycleDriver{closed: &closed} }
	fleet := NewFleet(Config{MaxConcurrency: 1, RecycleAfter: 3}, factory, nil, quiet())

	for i := 0; i < 7; i++ {
		if _, err := fleet.Run(context.Background(), "t1", trivialScript()); err != nil {
			t.Fatalf("run %d: %v", i, err)
		}
	}
	// 7 runs, recycle every 3 → drivers built for runs 1,4,7 = 3; closed = 2.
	if c := atomic.LoadInt32(&created); c != 3 {
		t.Fatalf("created drivers = %d, want 3", c)
	}
	if c := atomic.LoadInt32(&closed); c != 2 {
		t.Fatalf("closed drivers = %d, want 2", c)
	}
	fleet.Close()
	if c := atomic.LoadInt32(&closed); c != 3 {
		t.Fatalf("after Close, closed = %d, want 3", c)
	}
}

// A run that exceeds RunTimeout fails (isolated) and the worker is recycled.
func TestFleetRunTimeoutIsolatesAndRecycles(t *testing.T) {
	var created, closed int32
	factory := func() Driver {
		atomic.AddInt32(&created, 1)
		return &lifecycleDriver{closed: &closed, sleep: 200 * time.Millisecond}
	}
	fleet := NewFleet(Config{MaxConcurrency: 1, RunTimeout: 20 * time.Millisecond}, factory, nil, quiet())
	defer fleet.Close()

	res, err := fleet.Run(context.Background(), "t1", trivialScript())
	if err != nil {
		t.Fatalf("fleet.Run should not return an infra error for a per-run timeout: %v", err)
	}
	if res.Success {
		t.Fatal("a timed-out run must be reported as a failure")
	}
	// The slow worker was recycled, so the next run builds a fresh driver.
	_, _ = fleet.Run(context.Background(), "t1", trivialScript())
	if c := atomic.LoadInt32(&created); c < 2 {
		t.Fatalf("timed-out worker should have been recycled (created=%d)", c)
	}
}

// A failure run's artifact is uploaded to the object store under the tenant prefix.
func TestFleetStoresFailureArtifact(t *testing.T) {
	store := objectstore.NewMemory()
	factory := func() Driver { return &lifecycleDriver{screenshot: []byte("PNGBYTES"), fail: true} }
	fleet := NewFleet(Config{MaxConcurrency: 1}, factory, store, quiet())
	defer fleet.Close()

	res, _ := fleet.Run(context.Background(), "t9", trivialScript())
	if res.Screenshot == nil || res.Screenshot.ContentType != "image/png" || res.Screenshot.SizeBytes != 8 {
		t.Fatalf("screenshot ref: %+v", res.Screenshot)
	}
	if store.Len() != 1 {
		t.Fatalf("artifact not stored (len=%d)", store.Len())
	}
	obj, err := store.Get(context.Background(), res.Screenshot.Key)
	if err != nil || string(obj.Data) != "PNGBYTES" {
		t.Fatalf("stored artifact: %q err=%v", obj.Data, err)
	}
}

type objectPrefixRouter struct{ prefix string }

func (r objectPrefixRouter) TargetsFor(context.Context, string) (tenancy.Targets, error) {
	return tenancy.Targets{Model: tenancy.IsolationHybrid, ObjectPrefix: r.prefix}, nil
}

func (objectPrefixRouter) BusNamespaces(context.Context) ([]string, error) { return nil, nil }

func (objectPrefixRouter) BusNamespaceTenants(context.Context) (map[string]string, error) {
	return nil, nil
}

func TestFleetStoresFailureArtifactInRoutedNamespace(t *testing.T) {
	tenancy.SetRouter(objectPrefixRouter{prefix: "silo/t9"})
	t.Cleanup(func() { tenancy.SetRouter(nil) })

	store := objectstore.NewMemory()
	factory := func() Driver { return &lifecycleDriver{screenshot: []byte("PNGBYTES"), fail: true} }
	fleet := NewFleet(Config{MaxConcurrency: 1}, factory, store, quiet())
	defer fleet.Close()

	res, _ := fleet.Run(context.Background(), "t9", trivialScript())
	if res.Screenshot == nil || !strings.HasPrefix(res.Screenshot.Key, "silo/t9/browser/") {
		t.Fatalf("routed screenshot ref: %+v", res.Screenshot)
	}
	obj, err := store.Get(context.Background(), res.Screenshot.Key)
	if err != nil || string(obj.Data) != "PNGBYTES" {
		t.Fatalf("stored routed artifact: %q err=%v", obj.Data, err)
	}
	if keys, _ := store.List(context.Background(), "tenant/t9/"); len(keys) != 0 {
		t.Fatalf("routed tenant artifact must not fall back to pooled prefix: %v", keys)
	}
}

// A successful run does not store an artifact by default (bounds storage).
func TestFleetNoArtifactOnSuccessByDefault(t *testing.T) {
	store := objectstore.NewMemory()
	factory := func() Driver { return &lifecycleDriver{screenshot: []byte("x")} } // success
	fleet := NewFleet(Config{MaxConcurrency: 1}, factory, store, quiet())
	defer fleet.Close()

	res, _ := fleet.Run(context.Background(), "t1", trivialScript())
	if res.Screenshot != nil || store.Len() != 0 {
		t.Fatalf("success should not store an artifact: ref=%+v len=%d", res.Screenshot, store.Len())
	}
}
