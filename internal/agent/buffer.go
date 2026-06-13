// SPDX-License-Identifier: LicenseRef-probectl-TBD

package agent

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
)

// ErrBufferFull is returned by Enqueue when the buffer is at capacity (the
// control plane has been unreachable long enough to fill it). The caller sheds
// the newest result — bounded backpressure that keeps probing from growing
// unboundedly while offline.
var ErrBufferFull = errors.New("agent: store-and-forward buffer full")

const bufferFileName = "buffer.log"

// maxFrameLen bounds the length prefix readFrame will honor before allocating
// (RESIL-006). A corrupt or maliciously-large length prefix (a crash-torn tail,
// or a tampered buffer file on a customer host) would otherwise request up to
// ~4 GiB from a single uint32, OOM-ing the agent. Result payloads are small
// (protobuf probe results); 8 MiB is far above any legitimate frame, so an
// over-cap length is treated as a torn tail, not honored.
const maxFrameLen = 8 << 20 // 8 MiB

// ErrFrameTooLarge marks a length prefix that exceeds maxFrameLen. readAll
// treats it like any read error: the readable log ends there (torn tail).
var ErrFrameTooLarge = errors.New("agent: buffer frame length exceeds cap (corrupt/torn tail)")

// Buffer is a disk-backed, bounded, FIFO store-and-forward queue of result
// payloads. Results accumulate while the control plane is unreachable and drain
// in order on reconnect. The on-disk file holds exactly the undrained records as
// length-prefixed frames: [uint32 big-endian length][payload].
type Buffer struct {
	mu         sync.Mutex
	path       string
	maxRecords int
	fsync      bool
	count      int
	dropped    uint64
}

// OpenBuffer opens (creating if needed) a buffer in dir bounded to maxRecords. It
// compacts the file on open, discarding any torn tail frame left by a crash.
func OpenBuffer(dir string, maxRecords int) (*Buffer, error) {
	if maxRecords <= 0 {
		maxRecords = 10000
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("agent: buffer dir: %w", err)
	}
	b := &Buffer{path: filepath.Join(dir, bufferFileName), maxRecords: maxRecords, fsync: true}
	frames, err := b.readAll()
	if err != nil {
		return nil, err
	}
	if err := b.rewriteLocked(frames); err != nil {
		return nil, err
	}
	return b, nil
}

// Enqueue appends a payload, returning ErrBufferFull when at capacity.
func (b *Buffer) Enqueue(payload []byte) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.count >= b.maxRecords {
		b.dropped++
		return ErrBufferFull
	}
	f, err := os.OpenFile(b.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("agent: buffer open: %w", err)
	}
	defer f.Close()
	if err := writeFrame(f, payload); err != nil {
		return err
	}
	if b.fsync {
		if err := f.Sync(); err != nil {
			return fmt.Errorf("agent: buffer sync: %w", err)
		}
	}
	b.count++
	return nil
}

// Drain sends undrained records FIFO via send, stopping at the first send error
// or when ctx is canceled, then compacts the file to keep only the records that
// were NOT sent (plus any appended concurrently). It returns the number sent and
// the send error, if any. Enqueue is allowed during the (lock-free) send phase.
func (b *Buffer) Drain(ctx context.Context, send func([]byte) error) (int, error) {
	b.mu.Lock()
	frames, err := b.readAll()
	b.mu.Unlock()
	if err != nil {
		return 0, err
	}

	sent := 0
	var sendErr error
	for _, fr := range frames {
		if ctx.Err() != nil {
			sendErr = ctx.Err()
			break
		}
		if e := send(fr); e != nil {
			sendErr = e
			break
		}
		sent++
	}

	b.mu.Lock()
	defer b.mu.Unlock()
	cur, err := b.readAll()
	if err != nil {
		return sent, err
	}
	if sent > len(cur) {
		sent = len(cur)
	}
	if err := b.rewriteLocked(cur[sent:]); err != nil {
		return sent, err
	}
	return sent, sendErr
}

// Len returns the number of undrained records.
func (b *Buffer) Len() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.count
}

// Dropped returns the number of records shed due to overflow.
func (b *Buffer) Dropped() uint64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.dropped
}

// PeekAll returns all undrained records without removing them. With Remove this
// supports at-least-once forwarding: send a batch, get the control plane's ack,
// then remove exactly that many — a failure mid-batch retains everything to retry.
func (b *Buffer) PeekAll() ([][]byte, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.readAll()
}

// Remove drops the first n records (FIFO), keeping any appended since the Peek.
func (b *Buffer) Remove(n int) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	cur, err := b.readAll()
	if err != nil {
		return err
	}
	if n > len(cur) {
		n = len(cur)
	}
	return b.rewriteLocked(cur[n:])
}

// readAll reads every readable frame from the buffer file. A torn tail frame
// (crash mid-append) ends the readable log.
func (b *Buffer) readAll() ([][]byte, error) {
	f, err := os.Open(b.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("agent: buffer read: %w", err)
	}
	defer f.Close()
	var frames [][]byte
	for {
		fr, err := readFrame(f)
		if err != nil {
			break // io.EOF or a torn tail
		}
		frames = append(frames, fr)
	}
	return frames, nil
}

// rewriteLocked atomically replaces the buffer file with frames and updates count.
func (b *Buffer) rewriteLocked(frames [][]byte) error {
	tmp := b.path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("agent: buffer rewrite: %w", err)
	}
	for _, fr := range frames {
		if err := writeFrame(f, fr); err != nil {
			_ = f.Close()
			return err
		}
	}
	if b.fsync {
		if err := f.Sync(); err != nil {
			_ = f.Close()
			return fmt.Errorf("agent: buffer sync: %w", err)
		}
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, b.path); err != nil {
		return fmt.Errorf("agent: buffer rename: %w", err)
	}
	b.count = len(frames)
	return nil
}

func writeFrame(w io.Writer, payload []byte) error {
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(payload)))
	if _, err := w.Write(hdr[:]); err != nil {
		return fmt.Errorf("agent: buffer write header: %w", err)
	}
	if _, err := w.Write(payload); err != nil {
		return fmt.Errorf("agent: buffer write payload: %w", err)
	}
	return nil
}

func readFrame(r io.Reader) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	// RESIL-006: bound the allocation. A corrupt length prefix (e.g. 0xFFFFFFFF)
	// must not drive a multi-GiB make() and OOM the agent — treat an over-cap
	// length as a torn tail (the caller stops reading on any error).
	if n > maxFrameLen {
		return nil, ErrFrameTooLarge
	}
	payload := make([]byte, n)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, err
	}
	return payload, nil
}
