// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package l7

import (
	"encoding/binary"
	"time"

	"github.com/twmb/franz-go/pkg/kmsg"
)

// kafkaParser parses the Kafka wire protocol at the header level: it matches a
// response to its request by correlation id and reports the API name (Produce,
// Fetch, …) as the method plus the latency. Per-partition error codes live deep
// in version-specific response bodies and are out of scope for S21 (documented).
type kafkaParser struct {
	reqBuf, respBuf []byte
	pending         map[int32]kafkaReq
}

type kafkaReq struct {
	api   string
	start time.Time
	bytes uint64
}

func newKafkaParser() *kafkaParser { return &kafkaParser{pending: map[int32]kafkaReq{}} }

func (p *kafkaParser) OnData(d DataEvent) []Call {
	if d.Kind == Request {
		// FUZZ-001: cap the request buffer (kafka already caps a single message
		// at 100 MiB, but a stream of partial frames could still accrete).
		if len(p.reqBuf)+len(d.Payload) > l7MaxBufBytes {
			p.reqBuf = p.reqBuf[:0]
			return nil
		}
		p.reqBuf = append(p.reqBuf, d.Payload...)
		for {
			msg, rest, ok := scanKafkaMessage(p.reqBuf)
			if !ok {
				break
			}
			p.reqBuf = rest
			// [int32 size][int16 api_key][int16 api_version][int32 correlation_id]…
			if len(msg) >= 12 {
				apiKey := int16(binary.BigEndian.Uint16(msg[4:6]))
				corr := int32(binary.BigEndian.Uint32(msg[8:12]))
				// FUZZ-001: cap in-flight requests whose responses never arrive
				// (a flood of distinct correlation ids). Evict the oldest first.
				if len(p.pending) >= l7MaxPending {
					p.evictOldest()
				}
				p.pending[corr] = kafkaReq{api: kmsg.NameForKey(apiKey), start: d.Time, bytes: uint64(len(msg))}
			}
		}
		return nil
	}

	var calls []Call
	if len(p.respBuf)+len(d.Payload) > l7MaxBufBytes {
		p.respBuf = p.respBuf[:0]
		return nil
	}
	p.respBuf = append(p.respBuf, d.Payload...)
	for {
		msg, rest, ok := scanKafkaMessage(p.respBuf)
		if !ok {
			break
		}
		p.respBuf = rest
		// [int32 size][int32 correlation_id]…
		if len(msg) >= 8 {
			corr := int32(binary.BigEndian.Uint32(msg[4:8]))
			if req, ok := p.pending[corr]; ok {
				delete(p.pending, corr)
				calls = append(calls, Call{
					Protocol:  ProtoKafka,
					Method:    req.api,
					Start:     req.start,
					Latency:   d.Time.Sub(req.start),
					ReqBytes:  req.bytes,
					RespBytes: uint64(len(msg)),
				})
			}
		}
	}
	return calls
}

func (p *kafkaParser) Flush() []Call { return nil }

// evictOldest drops the least-recently-started pending request (FUZZ-001),
// bounding the map under a flood of unmatched correlation ids.
func (p *kafkaParser) evictOldest() {
	var oldestCorr int32
	var oldest time.Time
	first := true
	for corr, r := range p.pending {
		if first || r.start.Before(oldest) {
			oldestCorr, oldest, first = corr, r.start, false
		}
	}
	if !first {
		delete(p.pending, oldestCorr)
	}
}

// scanKafkaMessage returns one complete length-prefixed message ([int32 size]
// [payload]), or ok=false if not fully captured. The returned slice includes the
// 4-byte size prefix.
func scanKafkaMessage(buf []byte) (msg, rest []byte, ok bool) {
	if len(buf) < 4 {
		return nil, buf, false
	}
	size := int(binary.BigEndian.Uint32(buf[0:4]))
	total := 4 + size
	if size < 0 || size > 100<<20 || total > len(buf) { // 100 MiB sanity cap
		return nil, buf, false
	}
	return buf[:total], buf[total:], true
}
