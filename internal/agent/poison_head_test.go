// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package agent

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestAuditS1PoisonHeadFrameWedgesDrainForever is the ING-28 regression: a
// single undecodable HEAD frame used to wedge the store-and-forward drain
// forever. frameRequestsPrefix converts only the contiguous GOOD prefix, so an
// undecodable frames[0] left that prefix empty, drainOnce returned without
// removing anything, and once the buffer filled every new result was shed with
// ErrBufferFull. The fix quarantines the poison head so draining resumes.
//
// This test enqueues a poison head frame ahead of good frames, fills the
// buffer, runs drain cycles, and asserts draining PROGRESSES: the poison head is
// quarantined (counter increments, bytes preserved to the sidecar), the good
// frames behind it drain, and the buffer is no longer wedged full. Before the
// fix the first assertion fails (quarantined = 0; the buffer stays full and a
// fresh Enqueue keeps returning ErrBufferFull).
func TestAuditS1PoisonHeadFrameWedgesDrainForever(t *testing.T) {
	const capacity = 5
	dir := t.TempDir()
	buf, err := OpenBufferWithBytes(dir, capacity, -1)
	if err != nil {
		t.Fatal(err)
	}
	buf.fsync = false

	// Head frame is undecodable JSON: frameToRequest can never convert it.
	poison := []byte("}{ not a valid result envelope")
	if err := buf.Enqueue(poison); err != nil {
		t.Fatal(err)
	}
	goodCount := capacity - 1
	for i := 0; i < goodCount; i++ {
		frame := mustMarshalResultEnvelope(t, testResultEnvelope("tenant-poison", "agent-poison", fmt.Sprintf("good-%d", i)))
		if err := buf.Enqueue(frame); err != nil {
			t.Fatal(err)
		}
	}
	// Precondition: the buffer is full, so a fresh result is shed with
	// ErrBufferFull until draining frees a slot.
	if err := buf.Enqueue([]byte("overflow-while-full")); !errors.Is(err, ErrBufferFull) {
		t.Fatalf("precondition: full-buffer Enqueue = %v, want ErrBufferFull", err)
	}

	a := &Agent{
		cfg: &Config{Buffer: BufferConfig{
			DrainMaxRecords: capacity,
			DrainMaxBytes:   64 << 20,
			DrainPace:       Duration(time.Nanosecond),
		}},
		buffer: buf,
		log:    slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	client := &fakeDrainClient{}

	// Run a bounded number of drain cycles. The fix makes each cycle make
	// progress; the bug makes every cycle an identical no-op.
	for cycle := 0; cycle < capacity+2 && buf.Len() > 0; cycle++ {
		if err := a.drainOnce(context.Background(), client); err != nil {
			t.Fatalf("cycle %d: drainOnce: %v", cycle, err)
		}
	}

	// Draining PROGRESSED: the poison head frame was quarantined exactly once.
	if got := buf.Quarantined(); got != 1 {
		t.Fatalf("quarantined = %d, want 1 (poison head frame wedged the drain forever)", got)
	}
	// The good frames behind it all drained.
	if got := buf.Len(); got != 0 {
		t.Fatalf("buffer len after drain cycles = %d, want 0 (good frames stuck behind poison head)", got)
	}
	if len(client.streams) == 0 {
		t.Fatal("no StreamResults opened: drain never progressed past the poison head frame")
	}
	streamed := 0
	for _, s := range client.streams {
		streamed += len(s.sent)
	}
	if streamed != goodCount {
		t.Fatalf("good frames streamed = %d, want %d", streamed, goodCount)
	}
	// The buffer is no longer wedged full: a fresh result now enqueues.
	nextGood := mustMarshalResultEnvelope(t, testResultEnvelope("tenant-poison", "agent-poison", "post-drain"))
	if err := buf.Enqueue(nextGood); err != nil {
		t.Fatalf("post-drain Enqueue = %v, want nil (buffer should no longer be full)", err)
	}

	// The poison bytes were preserved to the sidecar, not destroyed.
	data, err := os.ReadFile(filepath.Join(dir, quarantineFileName))
	if err != nil {
		t.Fatalf("read quarantine sidecar: %v", err)
	}
	if !bytes.Contains(data, poison) {
		t.Fatal("quarantine sidecar does not contain the poison head frame bytes")
	}
}
