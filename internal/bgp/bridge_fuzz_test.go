// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package bgp

import (
	"bytes"
	"context"
	"testing"
)

// FuzzIngest hardens the analyzer→bus boundary, which parses untrusted JSON-Lines.
// Two invariants must hold for any input: Ingest never panics, and it never
// publishes an event with an empty tenant key — the fail-closed tenant guarantee
// (docs/guardrails.md G7-1) must survive arbitrary/adversarial input.
func FuzzIngest(f *testing.F) {
	f.Add([]byte(originChange + "\n"))
	f.Add([]byte("{ not json\n"))
	f.Add([]byte(`{"tenant_id":"","event_type":"origin_change","prefix":"p"}` + "\n"))
	f.Add([]byte(`{"tenant_id":"t1","event_type":"possible_hijack","prefix":"192.0.2.0/24"}` + "\n"))
	f.Add([]byte(""))

	f.Fuzz(func(t *testing.T, data []byte) {
		pub := &capturePublisher{}
		br := NewBridge(pub, discardLogger())

		_, _ = br.Ingest(context.Background(), bytes.NewReader(data))

		for _, m := range pub.msgs {
			if len(m.key) == 0 {
				t.Fatalf("fail-closed violated: published an event with an empty tenant key (value=%q)", m.value)
			}
		}
	})
}
