// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package bgp

import (
	"bytes"
	"context"
	"testing"
)

// FuzzIngest hardens the analyzer→bus boundary, which parses untrusted JSON-Lines.
// Two invariants must hold for any input: Ingest never panics, and it never
// publishes an event with an empty tenant key — the fail-closed tenant guarantee
// (CLAUDE.md §7 guardrail 1) must survive arbitrary/adversarial input.
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
