// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

// TestExtendWriteDeadlineSurvivesWriteTimeout is the WEB-04 regression: the
// server's absolute WriteTimeout reset any response not fully delivered within
// the (default 15s) window — aborting path discovery, remote-model AI answers,
// and large/slow exports mid-flight. extendWriteDeadline lifts that deadline for
// a long-running response. The control (no extension) proves the WriteTimeout is
// real and that the extension is what saves the response.
func TestExtendWriteDeadlineSurvivesWriteTimeout(t *testing.T) {
	const body = "RESPONSE-BODY-OK"
	mux := http.NewServeMux()
	// Long handler: starts work, extends the deadline, then responds after the
	// short global WriteTimeout would have fired.
	mux.HandleFunc("/extend", func(w http.ResponseWriter, _ *http.Request) {
		extendWriteDeadline(w, 5*time.Second)
		time.Sleep(600 * time.Millisecond)
		_, _ = io.WriteString(w, body)
	})
	// Control handler: same timing, no extension — must be cut off at the
	// WriteTimeout.
	mux.HandleFunc("/plain", func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(600 * time.Millisecond)
		_, _ = io.WriteString(w, body)
	})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &http.Server{Handler: mux, WriteTimeout: 200 * time.Millisecond}
	go func() { _ = srv.Serve(ln) }()
	defer srv.Close()
	base := "http://" + ln.Addr().String()

	get := func(path string) (string, error) {
		resp, err := http.Get(base + path)
		if err != nil {
			return "", err
		}
		defer resp.Body.Close()
		b, err := io.ReadAll(resp.Body)
		return string(b), err
	}

	// The extended response is delivered in full despite exceeding the 200ms
	// WriteTimeout.
	got, err := get("/extend")
	if err != nil || got != body {
		t.Fatalf("extended long response did not complete: body=%q err=%v (WriteTimeout reset a response extendWriteDeadline should have protected)", got, err)
	}
	// The un-extended response is cut off at the WriteTimeout (truncated body or
	// a read/connection error) — proving the deadline is real.
	if got, err := get("/plain"); err == nil && strings.Contains(got, body) {
		t.Fatalf("un-extended long response unexpectedly completed in full (%q); the WriteTimeout is not enforced, so the test proves nothing", got)
	}
}
