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
