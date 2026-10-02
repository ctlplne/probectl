// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package crypto

import (
	"context"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"
)

// GuardedHTTPClient must refuse a connection whose resolved address is in a
// reserved range (loopback/link-local/metadata/private) BEFORE the socket is
// opened — the SSRF guard that protects tenant-controlled egress (webhooks).
func TestGuardedHTTPClientBlocksReservedDestinationsPreConnect(t *testing.T) {
	// A real loopback listener: if the guard worked, it never accepts.
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

	c := GuardedHTTPClient(3 * time.Second)
	for _, url := range []string{
		"https://" + ln.Addr().String(), // loopback (real listener)
		"https://169.254.169.254/",      // cloud metadata (link-local)
		"https://10.0.0.1/",             // RFC1918
		"https://[::1]/",                // IPv6 loopback
		"http://127.0.0.1:1/",           // this-network / loopback
	} {
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
		resp, err := c.Do(req)
		if err == nil {
			resp.Body.Close()
			t.Fatalf("request to %s was not blocked", url)
		}
	}
	time.Sleep(50 * time.Millisecond)
	if accepted.Load() {
		t.Fatal("the guarded dialer opened a socket to the loopback listener")
	}
}
