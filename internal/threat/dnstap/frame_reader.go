// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package dnstap

import (
	"encoding/binary"
	"errors"
	"io"
)

const (
	contentType      = "protobuf:dnstap.Dnstap"
	maxControl       = 512
	maxData          = 128 << 10
	controlStart     = 2
	controlStop      = 3
	contentTypeField = 1
)

var (
	ErrInvalidFrame = errors.New("dnstap: invalid Frame Streams record")
	ErrIncomplete   = errors.New("dnstap: capture ends before a complete stop frame")
)

// CaptureReader reads one immutable, bounded Frame Streams file. The resolver
// identity and tenant belong to the caller's verified enrollment, outside the
// input format. Decoder errors include only fixed messages.
type CaptureReader struct {
	source           io.Reader
	started, stopped bool
	failure          error
	data             [maxData]byte
}

func NewCaptureReader(source io.Reader) *CaptureReader {
	return &CaptureReader{source: source}
}

// Next reports the next data frame's reduced observation. Non-client-response
// messages are counted through Selected=false so callers can expose coverage.
func (r *CaptureReader) Next() (ResolverObservation, error) {
	out, err := r.next()
	if err != nil && !errors.Is(err, io.EOF) {
		r.failure = err
	}
	return out, err
}

func (r *CaptureReader) next() (ResolverObservation, error) {
	var out ResolverObservation
	if r.source == nil {
		return out, ErrInvalidFrame
	}
	if r.failure != nil {
		return out, r.failure
	}
	if r.stopped {
		return out, io.EOF
	}
	if !r.started {
		if err := r.readStart(); err != nil {
			return out, err
		}
		r.started = true
	}
	size, err := readSize(r.source)
	if err != nil {
		return out, err
	}
	if size == 0 {
		control, err := r.readControl()
		if err != nil {
			return out, err
		}
		if len(control) != 4 || binary.BigEndian.Uint32(control) != controlStop {
			return out, ErrInvalidFrame
		}
		if n, err := io.ReadFull(r.source, r.data[:1]); n != 0 || !errors.Is(err, io.EOF) {
			return out, ErrInvalidFrame
		}
		r.stopped = true
		return out, io.EOF
	}
	if size > maxData {
		return out, ErrInvalidFrame
	}
	payload := r.data[:int(size)]
	if _, err := io.ReadFull(r.source, payload); err != nil {
		clear(payload)
		return out, ErrIncomplete
	}
	out, err = decodeResolverObservation(payload)
	clear(payload)
	return out, err
}

func (r *CaptureReader) readStart() error {
	escape, err := readSize(r.source)
	if err != nil {
		return err
	}
	if escape != 0 {
		return ErrInvalidFrame
	}
	frame, err := r.readControl()
	if err != nil {
		return err
	}
	if len(frame) != 12+len(contentType) || binary.BigEndian.Uint32(frame[:4]) != controlStart ||
		binary.BigEndian.Uint32(frame[4:8]) != contentTypeField || binary.BigEndian.Uint32(frame[8:12]) != uint32(len(contentType)) ||
		string(frame[12:]) != contentType {
		return ErrInvalidFrame
	}
	return nil
}

func (r *CaptureReader) readControl() ([]byte, error) {
	size, err := readSize(r.source)
	if err != nil {
		return nil, err
	}
	if size < 4 || size > maxControl {
		return nil, ErrInvalidFrame
	}
	control := r.data[:int(size)]
	if _, err := io.ReadFull(r.source, control); err != nil {
		return nil, ErrIncomplete
	}
	return control, nil
}

func readSize(source io.Reader) (uint32, error) {
	var wire [4]byte
	if _, err := io.ReadFull(source, wire[:]); err != nil {
		return 0, ErrIncomplete
	}
	return binary.BigEndian.Uint32(wire[:]), nil
}
