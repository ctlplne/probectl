// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package dnstap

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/miekg/dns"
	"google.golang.org/protobuf/encoding/protowire"
)

func captureControl(dst []byte, frame []byte) []byte {
	dst = binary.BigEndian.AppendUint32(dst, 0)
	dst = binary.BigEndian.AppendUint32(dst, uint32(len(frame)))
	return append(dst, frame...)
}

func ordinaryResolverCapture(t *testing.T) ([]byte, time.Time) {
	t.Helper()
	started := binary.BigEndian.AppendUint32(nil, 2)
	started = binary.BigEndian.AppendUint32(started, 1)
	started = binary.BigEndian.AppendUint32(started, uint32(len(contentType)))
	started = append(started, contentType...)
	out := captureControl(nil, started)
	at := time.Date(2026, 11, 20, 3, 0, 0, 1, time.UTC)
	var reply dns.Msg
	reply.SetQuestion("local-resolver-probe.test.", dns.TypeA)
	reply.Response = true
	reply.Rcode = dns.RcodeNameError
	wire, err := reply.Pack()
	if err != nil {
		t.Fatal(err)
	}
	event := protowire.AppendVarint(protowire.AppendTag(nil, 1, protowire.VarintType), 6)
	event = protowire.AppendVarint(protowire.AppendTag(event, 12, protowire.VarintType), uint64(at.Unix()))
	event = protowire.AppendFixed32(protowire.AppendTag(event, 13, protowire.Fixed32Type), uint32(at.Nanosecond()))
	event = protowire.AppendBytes(protowire.AppendTag(event, 14, protowire.BytesType), wire)
	body := protowire.AppendBytes(protowire.AppendTag(nil, 14, protowire.BytesType), event)
	body = protowire.AppendVarint(protowire.AppendTag(body, 15, protowire.VarintType), 1)
	out = binary.BigEndian.AppendUint32(out, uint32(len(body)))
	out = append(out, body...)
	return captureControl(out, binary.BigEndian.AppendUint32(nil, 3)), at
}

func TestResolverCaptureKeepsOnlyReducedClientResponseAndExactClock(t *testing.T) {
	data, at := ordinaryResolverCapture(t)
	source := NewCaptureReader(bytes.NewReader(data))
	value, err := source.Next()
	if err != nil || value != (ResolverObservation{Selected: true, ObservedAt: at, ResponseCode: dns.RcodeNameError, QuestionType: dns.TypeA}) {
		t.Fatal("valid client response lost its original clock or status", value, err)
	}
	if _, err = source.Next(); !errors.Is(err, io.EOF) {
		t.Fatal("complete stream did not report a terminal stop", err)
	}
}

func TestResolverCaptureDistinguishesIncompleteAndInvalidFraming(t *testing.T) {
	complete, _ := ordinaryResolverCapture(t)
	for _, tc := range []struct {
		name      string
		file      []byte
		first     error
		following error
	}{
		{"missing stop", complete[:len(complete)-12], nil, ErrIncomplete},
		{"trailing bytes", append(bytes.Clone(complete), 1), nil, ErrInvalidFrame},
		{"oversize first frame", binary.BigEndian.AppendUint32(nil, 1<<25), ErrInvalidFrame, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			source := NewCaptureReader(bytes.NewReader(tc.file))
			if _, err := source.Next(); !errors.Is(err, tc.first) {
				t.Fatal("first coverage result", err, tc.first)
			}
			if tc.following != nil {
				for range 2 {
					if _, err := source.Next(); !errors.Is(err, tc.following) {
						t.Fatal("invalid end-of-capture became a clean EOF", err, tc.following)
					}
				}
			}
		})
	}
}
