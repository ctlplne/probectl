// SPDX-License-Identifier: LicenseRef-probectl-TBD

package agent

import (
	"context"
	"errors"
	"testing"
)

func enqueueN(t *testing.T, b *Buffer, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		if err := b.Enqueue([]byte{byte(i)}); err != nil {
			t.Fatalf("enqueue %d: %v", i, err)
		}
	}
}

func TestBufferEnqueueDrainFIFO(t *testing.T) {
	b, err := OpenBuffer(t.TempDir(), 100)
	if err != nil {
		t.Fatal(err)
	}
	enqueueN(t, b, 3)
	if b.Len() != 3 {
		t.Fatalf("len = %d, want 3", b.Len())
	}

	var got []byte
	sent, err := b.Drain(context.Background(), func(p []byte) error {
		got = append(got, p[0])
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if sent != 3 || b.Len() != 0 {
		t.Fatalf("sent=%d len=%d, want 3/0", sent, b.Len())
	}
	if len(got) != 3 || got[0] != 0 || got[2] != 2 {
		t.Errorf("FIFO order = %v", got)
	}
}

func TestBufferDrainAfterDisconnect(t *testing.T) {
	b, err := OpenBuffer(t.TempDir(), 100)
	if err != nil {
		t.Fatal(err)
	}
	enqueueN(t, b, 5)

	// Simulated outage: every send fails, so nothing drains and all records stay.
	sent, err := b.Drain(context.Background(), func([]byte) error {
		return errors.New("control plane unreachable")
	})
	if sent != 0 || err == nil {
		t.Fatalf("during outage sent=%d err=%v, want 0/non-nil", sent, err)
	}
	if b.Len() != 5 {
		t.Fatalf("len=%d after failed drain, want 5 (retained)", b.Len())
	}

	// Reconnect: the buffered records drain in order.
	var got []byte
	sent2, err := b.Drain(context.Background(), func(p []byte) error {
		got = append(got, p[0])
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if sent2 != 5 || b.Len() != 0 {
		t.Fatalf("after reconnect sent=%d len=%d, want 5/0", sent2, b.Len())
	}
	if got[0] != 0 || got[4] != 4 {
		t.Errorf("drained order = %v", got)
	}
}

func TestBufferPartialDrainKeepsRemainder(t *testing.T) {
	b, err := OpenBuffer(t.TempDir(), 100)
	if err != nil {
		t.Fatal(err)
	}
	enqueueN(t, b, 5)

	n := 0
	sent, _ := b.Drain(context.Background(), func([]byte) error {
		n++
		if n > 2 {
			return errors.New("boom")
		}
		return nil
	})
	if sent != 2 || b.Len() != 3 {
		t.Fatalf("sent=%d len=%d, want 2/3", sent, b.Len())
	}

	var got []byte
	if _, err := b.Drain(context.Background(), func(p []byte) error { got = append(got, p[0]); return nil }); err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || got[0] != 2 || got[2] != 4 {
		t.Errorf("remaining records = %v, want [2 3 4]", got)
	}
}

func TestBufferBoundedBackpressure(t *testing.T) {
	b, err := OpenBuffer(t.TempDir(), 2)
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Enqueue([]byte("a")); err != nil {
		t.Fatal(err)
	}
	if err := b.Enqueue([]byte("b")); err != nil {
		t.Fatal(err)
	}
	if err := b.Enqueue([]byte("c")); !errors.Is(err, ErrBufferFull) {
		t.Errorf("third enqueue = %v, want ErrBufferFull", err)
	}
	if b.Dropped() != 1 {
		t.Errorf("dropped = %d, want 1", b.Dropped())
	}
	if b.Len() != 2 {
		t.Errorf("len = %d, want 2", b.Len())
	}
}

// RESIL-009: the buffer is bounded by BYTES as well as record count. A run of
// large frames must be shed (counted) once the on-disk byte cap is hit, even
// though the record count is nowhere near its limit — pre-empting ENOSPC.
func TestBufferByteBoundRejectsAndCounts(t *testing.T) {
	// Record cap is high (1000) so only the byte cap can bite. Byte cap allows
	// ~2 frames of 100B payload (each frame = 4B header + 100B = 104B).
	b, err := OpenBufferWithBytes(t.TempDir(), 1000, 220)
	if err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, 100)
	if err := b.Enqueue(payload); err != nil { // 104B
		t.Fatal(err)
	}
	if err := b.Enqueue(payload); err != nil { // 208B
		t.Fatal(err)
	}
	if got := b.Bytes(); got != 208 {
		t.Fatalf("bytes = %d, want 208", got)
	}
	// Third would push to 312B > 220B cap → shed (record count is only 2).
	if err := b.Enqueue(payload); !errors.Is(err, ErrBufferFull) {
		t.Errorf("over-byte-cap enqueue = %v, want ErrBufferFull", err)
	}
	if b.Dropped() != 1 {
		t.Errorf("dropped = %d, want 1", b.Dropped())
	}
	if b.Len() != 2 {
		t.Errorf("len = %d, want 2 (byte cap, not record cap)", b.Len())
	}
}

// RESIL-009: a negative byte cap disables the byte bound (records-only).
func TestBufferNegativeBytesIsUnbounded(t *testing.T) {
	b, err := OpenBufferWithBytes(t.TempDir(), 1000, -1)
	if err != nil {
		t.Fatal(err)
	}
	big := make([]byte, 1<<20) // 1 MiB
	for i := 0; i < 5; i++ {
		if err := b.Enqueue(big); err != nil {
			t.Fatalf("enqueue %d with byte bound disabled = %v", i, err)
		}
	}
	if b.Len() != 5 {
		t.Errorf("len = %d, want 5", b.Len())
	}
}

func TestBufferPeekBatchHonorsRecordAndByteCaps(t *testing.T) {
	b, err := OpenBufferWithBytes(t.TempDir(), 1000, -1)
	if err != nil {
		t.Fatal(err)
	}
	b.fsync = false
	payload := make([]byte, 100)
	for i := 0; i < 10; i++ {
		if err := b.Enqueue(payload); err != nil {
			t.Fatal(err)
		}
	}
	byRecords, err := b.PeekBatch(3, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(byRecords) != 3 {
		t.Fatalf("record-bounded batch = %d, want 3", len(byRecords))
	}
	byBytes, err := b.PeekBatch(100, 250)
	if err != nil {
		t.Fatal(err)
	}
	if len(byBytes) != 2 { // each frame is 4-byte header + 100-byte payload
		t.Fatalf("byte-bounded batch = %d, want 2", len(byBytes))
	}
}

func TestBufferPersistsAcrossReopen(t *testing.T) {
	dir := t.TempDir()
	b, err := OpenBuffer(dir, 100)
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Enqueue([]byte("x")); err != nil {
		t.Fatal(err)
	}
	if err := b.Enqueue([]byte("y")); err != nil {
		t.Fatal(err)
	}

	b2, err := OpenBuffer(dir, 100) // simulate a restart
	if err != nil {
		t.Fatal(err)
	}
	if b2.Len() != 2 {
		t.Fatalf("len after reopen = %d, want 2", b2.Len())
	}
	var got []string
	if _, err := b2.Drain(context.Background(), func(p []byte) error { got = append(got, string(p)); return nil }); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != "x" || got[1] != "y" {
		t.Errorf("persisted records = %v", got)
	}
}
