// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package dnstap

import (
	"errors"
	"math"
	"time"

	"github.com/miekg/dns"
	"google.golang.org/protobuf/encoding/protowire"
)

const (
	envelopeMessage = 14
	envelopeType    = 15
	eventKind       = 1
	responseSeconds = 12
	responseNanos   = 13
	responseWire    = 14
	messageEnvelope = 1
	clientResponse  = 6
)

var ErrInvalidObservation = errors.New("dnstap: invalid resolver observation")

// ResolverObservation carries no DNS name, address, wire payload, label or
// tenant selector. Only resolver-to-client responses populate the counters.
type ResolverObservation struct {
	Selected     bool
	ObservedAt   time.Time
	ResponseCode uint16
	QuestionType uint16
	Truncated    bool
}

type wireField struct {
	number protowire.Number
	kind   protowire.Type
	value  []byte
}

func popField(raw []byte) (wireField, []byte, bool) {
	number, kind, tagSize := protowire.ConsumeTag(raw)
	if tagSize < 0 || kind == protowire.StartGroupType || kind == protowire.EndGroupType {
		return wireField{}, nil, false
	}
	raw = raw[tagSize:]
	valueSize := protowire.ConsumeFieldValue(number, kind, raw)
	if valueSize < 0 {
		return wireField{}, nil, false
	}
	return wireField{number, kind, raw[:valueSize]}, raw[valueSize:], true
}

func decodeResolverObservation(raw []byte) (ResolverObservation, error) {
	var out ResolverObservation
	var message []byte
	var typeSeen bool
	for len(raw) > 0 {
		field, rest, ok := popField(raw)
		if !ok {
			return out, ErrInvalidObservation
		}
		raw = rest
		switch field.number {
		case envelopeMessage:
			if field.kind != protowire.BytesType || message != nil {
				return out, ErrInvalidObservation
			}
			message, _ = protowire.ConsumeBytes(field.value)
			if len(message) == 0 {
				return out, ErrInvalidObservation
			}
		case envelopeType:
			kind, _ := protowire.ConsumeVarint(field.value)
			if field.kind != protowire.VarintType || typeSeen || kind != messageEnvelope {
				return out, ErrInvalidObservation
			}
			typeSeen = true
		}
	}
	if !typeSeen || message == nil {
		return out, ErrInvalidObservation
	}
	return decodeClientFields(message)
}

type clientFields struct {
	seen          uint16
	kind, seconds uint64
	nanos         uint32
	payload       []byte
}

func decodeClientFields(raw []byte) (ResolverObservation, error) {
	var empty ResolverObservation
	var event clientFields
	for len(raw) > 0 {
		field, rest, ok := popField(raw)
		if !ok || !event.record(field) {
			return empty, ErrInvalidObservation
		}
		raw = rest
	}
	if event.kind == 0 {
		return empty, ErrInvalidObservation
	}
	if event.kind != clientResponse {
		return empty, nil
	}
	return event.reduced()
}

func (e *clientFields) record(field wireField) bool {
	switch field.number {
	case eventKind, responseSeconds, responseNanos, responseWire:
		bit := uint16(1) << field.number
		if e.seen&bit != 0 {
			return false
		}
		e.seen |= bit
	default:
		return true
	}
	switch field.number {
	case eventKind:
		e.kind, _ = protowire.ConsumeVarint(field.value)
		return field.kind == protowire.VarintType
	case responseSeconds:
		e.seconds, _ = protowire.ConsumeVarint(field.value)
		return field.kind == protowire.VarintType
	case responseNanos:
		e.nanos, _ = protowire.ConsumeFixed32(field.value)
		return field.kind == protowire.Fixed32Type
	case responseWire:
		e.payload, _ = protowire.ConsumeBytes(field.value)
		return field.kind == protowire.BytesType
	default:
		return false
	}
}

func (e clientFields) reduced() (ResolverObservation, error) {
	var out ResolverObservation
	if e.seconds == 0 || e.seconds > math.MaxInt64/1_000_000_000 || e.nanos >= 1_000_000_000 ||
		e.seen&(1<<responseNanos) == 0 || len(e.payload) > 65535 || len(e.payload) < 12 {
		return out, ErrInvalidObservation
	}
	at := time.Unix(int64(e.seconds), int64(e.nanos)).UTC()
	if at.UnixNano() <= 0 || !time.Unix(0, at.UnixNano()).Equal(at) {
		return out, ErrInvalidObservation
	}
	var wire dns.Msg
	if err := wire.Unpack(e.payload); err != nil || !wire.Response || wire.Rcode < 0 || wire.Rcode > 4095 {
		return out, ErrInvalidObservation
	}
	out = ResolverObservation{Selected: true, ObservedAt: at, ResponseCode: uint16(wire.Rcode), Truncated: wire.Truncated}
	if len(wire.Question) == 1 {
		out.QuestionType = wire.Question[0].Qtype
	}
	return out, nil
}
