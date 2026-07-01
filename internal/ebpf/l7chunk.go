// SPDX-License-Identifier: LicenseRef-probectl-TBD

package ebpf

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/ebpf/l7"
)

// The earliest userspace boundary (EBPF-002): one ring-buffer record becomes
// one redacted L7Event HERE, before any parser, buffer, or forwarder can see
// a byte. The kernel already bounded what transits the ring (the capture
// window — body bytes past it never left the kernel); this boundary redacts
// what remains on the ONLY copy. Pure code so the no-plaintext-past-the-
// boundary property is unit-testable without a kernel.

// sslChunk mirrors struct tls_chunk in bpf/sslsniff.bpf.c — keep field
// order/sizes in sync.
type sslChunk struct {
	PID     uint32
	TID     uint32
	Conn    uint64
	IsRead  uint8
	Pad     [3]byte
	Len     uint32 // bytes copied by the kernel (Data[:Len] is the valid region)
	OrigLen uint32 // true plaintext size (volumetrics under any window)
	Data    [4096]byte
}

// decodeChunk parses a raw ring-buffer record and applies the redaction
// policy on the record's only surviving copy. The returned event's payload
// is redacted BEFORE this function returns — nothing upstream of it retains
// plaintext (raw is kernel-owned ring memory, reused on the next read).
func decodeChunk(raw []byte, tenantID, mode string) (L7Event, error) {
	return decodeChunkWithPolicy(raw, tenantID, mode, headerValuePolicy{})
}

func decodeChunkWithPolicy(raw []byte, tenantID, mode string, policy headerValuePolicy) (L7Event, error) {
	var c sslChunk
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &c); err != nil {
		return L7Event{}, fmt.Errorf("ebpf: decode tls chunk: %w", err)
	}
	kind := l7.Request
	if c.IsRead == 1 {
		kind = l7.Response
	}
	n := c.Len
	if n > uint32(len(c.Data)) {
		n = uint32(len(c.Data))
	}
	payload := redactPayloadWithPolicy(append([]byte(nil), c.Data[:n]...), mode, policy)
	return L7Event{
		ConnID:      c.Conn,
		TenantID:    tenantID,
		Encrypted:   true,
		Source:      Endpoint{PID: c.PID}, // 5-tuple correlation is the productionization step
		Destination: Endpoint{},
		Transport:   TransportTCP,
		Data: l7.DataEvent{
			Kind:    kind,
			Time:    time.Now(),
			Payload: payload,
			Size:    int(c.OrigLen),
		},
	}, nil
}
