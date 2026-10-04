// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package pipeline

import (
	"context"
	"io"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/ctlplne/probectl/internal/bus"
	resultv1 "github.com/ctlplne/probectl/internal/gen/probectl/result/v1"
	"github.com/ctlplne/probectl/internal/logging"
	"github.com/ctlplne/probectl/internal/store/tsdb"
)

// panicWriter panics on any series carrying panicOn as its tenant_id label, and
// delegates every other write to an inner store. It models a store-write path
// that blows up on one poison record (a decode/index bug, a nil deref) while
// healthy records keep flowing.
type panicWriter struct {
	inner   tsdb.Writer
	panicOn string
}

func (w *panicWriter) Write(ctx context.Context, series []tsdb.Series) error {
	for _, s := range series {
		if s.Labels["tenant_id"] == w.panicOn {
			panic("boom: injected write-stage panic on the poison tenant")
		}
	}
	return w.inner.Write(ctx, series)
}

func (w *panicWriter) Close() error { return w.inner.Close() }

// ING-40: the result write stage drains its bounded queue on worker goroutines
// the pipeline spawns ITSELF, outside any bus Subscribe handler. A panic in the
// store-write path there has no recover above it, so it crashed the whole
// process (and the handler blocked on <-it.done would hang). This drives the REAL
// Consumer.Run write stage with a store that panics on one record, and asserts
// the worker goroutine SURVIVES: a SUBSEQUENT good record is still stored, and
// the panic is counted (WriteStagePanics).
//
// Before the fix the write-stage worker panics unrecovered and crashes the test
// PROCESS, so the good record below is never stored and this test never reaches
// its assertions. After the fix the panic is recovered, the record is failed, and
// the good record lands.
func TestWriteStagePanicDoesNotCrashProcess(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	b := bus.NewMemory()
	defer b.Close()
	inner := tsdb.NewMemory()
	w := &panicWriter{inner: inner, panicOn: "poison"}
	c := NewConsumer(b, w, "test", logging.New(io.Discard, "error", "json")).WithTenantBinding(allowAllBinding{})

	var runWG sync.WaitGroup
	runWG.Add(1)
	go func() { defer runWG.Done(); _ = c.Run(ctx) }()
	if !b.WaitForSubscribers(ctx, bus.NetworkResultsTopic, 1) {
		t.Fatal("consumer did not subscribe to the network results topic")
	}

	// A record whose store write PANICS in the write-stage worker goroutine.
	poison, err := proto.Marshal(&resultv1.Result{TenantId: "poison", AgentId: "a1", CanaryType: "noop", Success: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Publish(ctx, bus.NetworkResultsTopic, []byte("poison"), poison); err != nil {
		t.Fatal(err)
	}
	// A subsequent GOOD record must still be stored — proving the write-stage
	// worker survived the panic and kept draining its queue.
	good, err := proto.Marshal(&resultv1.Result{TenantId: "good", AgentId: "a1", CanaryType: "noop", Success: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Publish(ctx, bus.NetworkResultsTopic, []byte("good"), good); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if len(inner.Query("probectl_probe_success", map[string]string{"tenant_id": "good"})) > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	runWG.Wait()

	if got := inner.Query("probectl_probe_success", map[string]string{"tenant_id": "good"}); len(got) == 0 {
		t.Fatal("subsequent good record was never stored — the write-stage worker did not survive the panic")
	}
	if st := c.Stats(); st.WriteStagePanics == 0 {
		t.Fatalf("write-stage panic was not counted: %+v", st)
	}
}
