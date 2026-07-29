// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package mcp

import (
	"context"
	"testing"
)

func BenchmarkHandlePing(b *testing.B) {
	s := newTestServer(&fakeBackend{}, testGate())
	p := principal("tenant-a")
	raw := []byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)
	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if out := s.Handle(ctx, p, raw); len(out) == 0 {
			b.Fatal("empty ping response")
		}
	}
}

func BenchmarkHandleToolCallListTests(b *testing.B) {
	s := newTestServer(&fakeBackend{}, testGate())
	p := principal("tenant-a", permTestRead)
	raw := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_tests","arguments":{}}}`)
	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if out := s.Handle(ctx, p, raw); len(out) == 0 {
			b.Fatal("empty tool response")
		}
	}
}
