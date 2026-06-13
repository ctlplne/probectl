// SPDX-License-Identifier: LicenseRef-probectl-TBD

package agent

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
)

// TestReadFrame_CorruptLengthIsTornTail is the RESIL-006 acceptance test: a
// frame whose length prefix is 0xFFFFFFFF (~4 GiB) followed by a few bytes must
// NOT drive an unbounded allocation. readFrame caps the length and reports a
// torn tail instead of OOM-ing the agent.
func TestReadFrame_CorruptLengthIsTornTail(t *testing.T) {
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], 0xFFFFFFFF)
	r := bytes.NewReader(append(hdr[:], 1, 2, 3, 4))

	got, err := readFrame(r)
	if err == nil {
		t.Fatalf("readFrame accepted a 4 GiB length prefix (allocated %d bytes); want ErrFrameTooLarge", len(got))
	}
	if !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("err = %v, want ErrFrameTooLarge", err)
	}
}

// TestReadFrame_JustOverCapRejected: a length just above the cap is rejected
// without allocating.
func TestReadFrame_JustOverCapRejected(t *testing.T) {
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], maxFrameLen+1)
	r := bytes.NewReader(hdr[:])
	if _, err := readFrame(r); !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("err = %v, want ErrFrameTooLarge for length cap+1", err)
	}
}

// TestReadFrame_AtCapAccepted: a legitimate frame at the cap round-trips.
func TestReadFrame_AtCapRoundTrips(t *testing.T) {
	payload := bytes.Repeat([]byte("x"), 1024)
	var buf bytes.Buffer
	if err := writeFrame(&buf, payload); err != nil {
		t.Fatal(err)
	}
	got, err := readFrame(&buf)
	if err != nil {
		t.Fatalf("readFrame on a valid 1 KiB frame: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("round-trip mismatch")
	}
}
