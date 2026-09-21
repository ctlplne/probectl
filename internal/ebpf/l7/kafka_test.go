// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package l7

import (
	"encoding/binary"
	"testing"
	"time"
)

func kafkaReqBytes(apiKey, apiVersion int16, corr int32) []byte {
	body := make([]byte, 8) // api_key(2) api_version(2) correlation_id(4)
	binary.BigEndian.PutUint16(body[0:2], uint16(apiKey))
	binary.BigEndian.PutUint16(body[2:4], uint16(apiVersion))
	binary.BigEndian.PutUint32(body[4:8], uint32(corr))
	out := make([]byte, 4+len(body))
	binary.BigEndian.PutUint32(out[0:4], uint32(len(body)))
	copy(out[4:], body)
	return out
}

func kafkaRespBytes(corr int32) []byte {
	body := make([]byte, 4)
	binary.BigEndian.PutUint32(body, uint32(corr))
	out := make([]byte, 4+len(body))
	binary.BigEndian.PutUint32(out[0:4], uint32(len(body)))
	copy(out[4:], body)
	return out
}

func TestKafkaApiNameAndLatency(t *testing.T) {
	p := newKafkaParser()
	t0 := time.Unix(0, 0)
	// api_key 1 = Fetch
	p.OnData(DataEvent{Kind: Request, Time: t0, Payload: kafkaReqBytes(1, 12, 99)})
	calls := p.OnData(DataEvent{Kind: Response, Time: t0.Add(7 * time.Millisecond), Payload: kafkaRespBytes(99)})
	if len(calls) != 1 {
		t.Fatalf("calls = %d, want 1", len(calls))
	}
	c := calls[0]
	if c.Protocol != ProtoKafka || c.Method != "Fetch" || c.Latency != 7*time.Millisecond {
		t.Errorf("call = %+v", c)
	}
}
