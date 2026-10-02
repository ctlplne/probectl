// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package alert

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// A webhook URL is tenant-controlled. The channel must refuse a plaintext
// http:// endpoint and must not open a socket to a loopback/link-local/metadata/
// private destination (SSRF). It uses the real SSRF-guarded client (nil Doer).
func TestWebhookChannelRefusesSSRFAndPlainHTTP(t *testing.T) {
	a := Alert{RuleID: "r1", State: StateFiring, At: time.Unix(1_700_000_000, 0)}

	// A real loopback listener: the guard must never let the channel connect.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	var accepted atomic.Bool
	go func() {
		if c, err := ln.Accept(); err == nil {
			accepted.Store(true)
			c.Close()
		}
	}()

	cases := []string{
		"http://example.com/hook",       // plaintext to a public host: refused
		"https://" + ln.Addr().String(), // loopback (real listener)
		"https://169.254.169.254/hook",  // cloud metadata (link-local)
		"https://10.1.2.3/hook",         // RFC1918
		"http://127.0.0.1:1/hook",       // plaintext + loopback
	}
	for _, url := range cases {
		ch := NewWebhookChannel(url, "", nil) // nil => real GuardedHTTPClient
		if err := ch.Notify(context.Background(), a); err == nil {
			t.Fatalf("webhook to %s was not refused", url)
		}
	}
	time.Sleep(50 * time.Millisecond)
	if accepted.Load() {
		t.Fatal("the webhook channel opened a socket to the loopback listener")
	}
}
