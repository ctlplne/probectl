// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package browser

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestSocketDriverSpeaksTheWorkerContract closes the SUP-02 / D-36 transport
// half: the sidecar SocketDriver must hand the worker the SAME Script contract
// ExecDriver does AND carry the per-transaction options (step timeout,
// allow-private-targets) IN-BAND — because the sidecar worker is one shared
// process, env cannot vary them per canary. A fake UNIX-socket worker stands in
// for Chromium (the real render is a cluster-pending proof); this pins the wire
// protocol both ends depend on.
func TestSocketDriverSpeaksTheWorkerContract(t *testing.T) {
	dir, err := os.MkdirTemp("", "bw")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	sock := filepath.Join(dir, "w.sock")

	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	type gotReq struct {
		Script              Script `json:"script"`
		StepTimeoutMs       int64  `json:"step_timeout_ms"`
		AllowPrivateTargets bool   `json:"allow_private_targets"`
	}
	reqCh := make(chan gotReq, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		raw, _ := io.ReadAll(conn) // reads to the driver's half-close
		var gr gotReq
		_ = json.Unmarshal(raw, &gr)
		reqCh <- gr
		// A canned worker result in the same JSON shape worker.mjs emits.
		_, _ = conn.Write([]byte(`{"success":true,"total_ms":42,` +
			`"steps":[{"name":"open","action":"goto","success":true}],` +
			`"waterfall":[],"screenshot_b64":"","screenshot_content_type":""}`))
		if cw, ok := conn.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
	}()

	d := NewSocketDriver(sock).WithStepTimeout(7 * time.Second).WithAllowPrivateTargets(true)
	if d.Name() != "playwright" {
		t.Errorf("Name() = %q, want playwright (Fleet keys result views on the driver name)", d.Name())
	}
	s := Script{Name: "t", StartURL: "https://example.com", Steps: []Step{{Name: "open", Action: Goto}}}
	out, err := d.Run(context.Background(), s)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	// The worker received the script AND the per-transaction options in-band.
	gr := <-reqCh
	if gr.Script.StartURL != "https://example.com" {
		t.Errorf("script not carried over the socket: %+v", gr.Script)
	}
	if gr.StepTimeoutMs != 7000 {
		t.Errorf("step_timeout_ms carried = %d, want 7000", gr.StepTimeoutMs)
	}
	if !gr.AllowPrivateTargets {
		t.Error("allow_private_targets must travel in-band per request (a shared sidecar worker cannot read it from per-canary env)")
	}

	// The worker's result was parsed and the script-derived fields filled.
	if !out.Result.Success {
		t.Error("worker Success not parsed")
	}
	if out.Result.Script != "t" || out.Result.Target != "https://example.com" {
		t.Errorf("script-derived fields not filled: %+v", out.Result)
	}
}

// TestSocketDriverDefaultsAllowPrivateFalse pins the secure default: a driver
// built without WithAllowPrivateTargets sends allow_private_targets=false, so the
// worker's SSRF guard stays on unless a canary explicitly opted in.
func TestSocketDriverDefaultsAllowPrivateFalse(t *testing.T) {
	dir, err := os.MkdirTemp("", "bw")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	sock := filepath.Join(dir, "w.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	seen := make(chan bool, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		raw, _ := io.ReadAll(conn)
		var gr struct {
			AllowPrivateTargets bool `json:"allow_private_targets"`
		}
		_ = json.Unmarshal(raw, &gr)
		seen <- gr.AllowPrivateTargets
		_, _ = conn.Write([]byte(`{"success":true,"steps":[],"waterfall":[]}`))
		if cw, ok := conn.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
	}()

	if _, err := NewSocketDriver(sock).Run(context.Background(), Script{Name: "t"}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if <-seen {
		t.Error("default SocketDriver sent allow_private_targets=true; the SSRF guard must default on")
	}
}
