// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package browser

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"time"
)

// socketRequest is the SocketDriver→worker wire envelope. It carries the Script
// plus the PER-TRANSACTION options that ExecDriver hands a fresh process as env
// (PROBECTL_BROWSER_STEP_TIMEOUT_MS / PROBECTL_BROWSER_ALLOW_PRIVATE_TARGETS).
// The sidecar worker is a SHARED, long-lived process, so these must travel
// in-band per request — otherwise a per-canary allow-private-targets value would
// collapse to one setting for the whole fleet, weakening the SSRF guard
// (docs/guardrails.md G7-10). The worker still runs the Go-side TargetGuard's
// already-validated script; allow_private_targets is the worker's defense-in-depth.
type socketRequest struct {
	Script              Script `json:"script"`
	StepTimeoutMs       int64  `json:"step_timeout_ms,omitempty"`
	AllowPrivateTargets bool   `json:"allow_private_targets"`
}

// SocketDriver runs a transaction by connecting to a browser-worker over a UNIX
// domain socket and speaking the SAME JSON contract as ExecDriver: it writes the
// socketRequest, half-closes the write side so the worker sees end-of-request,
// and reads the worker's Result JSON back.
//
// This is the sidecar-split transport (SUP-02 / design-partner-readiness D-36).
// ExecDriver spawns the Playwright worker as a child process and so must live in
// the SAME container as it — which means the agent's mTLS identity (key.pem) is
// readable by the Chromium renderer, and a browser RCE could exfiltrate it.
// SocketDriver instead drives a worker in a SEPARATE sidecar container that holds
// NO agent identity, over a shared-volume UNIX socket. One connection per
// transaction mirrors ExecDriver's one process per transaction; a Fleet
// RunTimeout (ctx cancel) closes the connection, aborting the worker's in-flight
// run (real isolation for the heaviest canary, preserved across the split).
type SocketDriver struct {
	socket       string
	stepTimeout  time.Duration
	allowPrivate bool
}

// NewSocketDriver drives the worker listening on the UNIX socket at path (the
// agent↔worker shared-volume socket, e.g. /run/browser-worker/worker.sock).
func NewSocketDriver(socket string) *SocketDriver {
	return &SocketDriver{socket: socket}
}

// WithStepTimeout sets the per-step timeout forwarded to the worker per request.
func (d *SocketDriver) WithStepTimeout(t time.Duration) *SocketDriver {
	d.stepTimeout = t
	return d
}

// WithAllowPrivateTargets forwards the per-transaction allow-private-targets flag
// to the worker's SSRF guard. Default false (private/link-local/loopback denied).
func (d *SocketDriver) WithAllowPrivateTargets(v bool) *SocketDriver {
	d.allowPrivate = v
	return d
}

func (*SocketDriver) Name() string { return "playwright" }

func (d *SocketDriver) Run(ctx context.Context, s Script) (RunOutput, error) {
	req := socketRequest{Script: s, AllowPrivateTargets: d.allowPrivate}
	if d.stepTimeout > 0 {
		req.StepTimeoutMs = d.stepTimeout.Milliseconds()
	}
	payload, err := json.Marshal(req)
	if err != nil {
		return RunOutput{}, err
	}

	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "unix", d.socket)
	if err != nil {
		return RunOutput{}, fmt.Errorf("browser worker: dial %s: %w", d.socket, err)
	}
	defer conn.Close()

	// A Fleet RunTimeout (ctx cancel/deadline) must tear the connection down so
	// the worker aborts the transaction rather than running past the budget.
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()

	start := time.Now()
	if _, err := conn.Write(payload); err != nil {
		return RunOutput{}, fmt.Errorf("browser worker: write request: %w", err)
	}
	// Half-close the write side: the worker reads to end-of-request, then runs and
	// replies. A *net.UnixConn implements CloseWrite.
	if cw, ok := conn.(interface{ CloseWrite() error }); ok {
		if err := cw.CloseWrite(); err != nil {
			return RunOutput{}, fmt.Errorf("browser worker: close write: %w", err)
		}
	}

	out, err := io.ReadAll(conn)
	if err != nil {
		return RunOutput{}, fmt.Errorf("browser worker: read result: %w", err)
	}
	if len(out) == 0 {
		return RunOutput{}, fmt.Errorf("browser worker: empty result from %s", d.socket)
	}
	return parseWorkerResult(out, s, start)
}
