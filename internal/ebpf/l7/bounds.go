// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package l7

// FUZZ-001: shared per-parser bounds. Each L7 parser holds per-connection state
// — request/response reassembly buffers and a map of in-flight requests awaiting
// their response. On a busy or hostile host these grow without limit: a peer
// that dribbles bytes but never completes a message pins the buffer; pipelined
// or correlation-id'd requests whose responses never arrive pin the pending map.
// The DNS parser already bounds its pending map (dnsMaxPending); these constants
// extend the same discipline to the HTTP/1, HTTP/2 and Kafka parsers. When a
// bound is hit we drop+reset (buffers) or evict the oldest (pending), never
// grow unbounded and never panic.
const (
	// l7MaxBufBytes caps a single direction's reassembly buffer. A real
	// request/response header+body fits well under this; exceeding it means a
	// non-conforming or adversarial stream, so reset rather than retain.
	l7MaxBufBytes = 1 << 20 // 1 MiB per direction

	// l7MaxPending caps in-flight requests awaiting a response, per parser.
	l7MaxPending = 4096
)
