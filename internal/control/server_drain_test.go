// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package control

import (
	"context"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/config"
	"github.com/ctlplne/probectl/internal/logging"
)

// TestDrainKeepsTheListenerOpenSoProbesSeeTheDrain (DPR-103): the documented
// zero-downtime roll says /healthz stays 200 while /readyz answers 503 on the
// draining replica. On the lab every terminating replica refused connections
// within a second instead, because the listener closed in the same instant
// readiness flipped. With a drain grace the window is observable: a fresh
// probe gets healthz 200 / readyz 503 first, and only then is the socket
// closed.
func TestDrainKeepsTheListenerOpenSoProbesSeeTheDrain(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{HTTPAddr: "127.0.0.1:0", AuthMode: "dev", ShutdownTimeout: 5 * time.Second, DrainGrace: 600 * time.Millisecond}
	srv := New(cfg, logging.New(io.Discard, "error", "json"), fakePinger{}, nil, nil, nil).WithListener(ln)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Run(ctx) }()
	base := "http://" + ln.Addr().String()
	get := func(path string) int {
		resp, err := http.Get(base + path)
		if err != nil {
			return 0
		}
		defer resp.Body.Close()
		return resp.StatusCode
	}
	deadline := time.Now().Add(3 * time.Second)
	for get("/healthz") != http.StatusOK {
		if time.Now().After(deadline) {
			t.Fatal("server never came up")
		}
		time.Sleep(10 * time.Millisecond)
	}

	cancel()
	time.Sleep(50 * time.Millisecond)
	if h, r := get("/healthz"), get("/readyz"); h != http.StatusOK || r != http.StatusServiceUnavailable {
		t.Fatalf("during the drain grace a fresh probe must see healthz 200 / readyz 503, got %d / %d", h, r)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("run: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server did not shut down after the drain grace")
	}
	if get("/healthz") != 0 {
		t.Fatal("after the drain grace the listener must be closed")
	}
}

// TestDrainGraceIsBoundedByTheShutdownTimeout: the window never eats more
// than half of the shutdown timeout, and 0 disables it.
func TestDrainGraceIsBoundedByTheShutdownTimeout(t *testing.T) {
	s := &Server{cfg: &config.Config{ShutdownTimeout: 4 * time.Second, DrainGrace: 10 * time.Second}}
	if got := s.drainGrace(); got != 2*time.Second {
		t.Fatalf("grace must be capped at half the shutdown timeout, got %s", got)
	}
	s.cfg.DrainGrace = 0
	if got := s.drainGrace(); got != 0 {
		t.Fatalf("0 must disable the window, got %s", got)
	}
}
