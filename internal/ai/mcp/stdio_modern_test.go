// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package mcp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/auth"
)

type stdioPipe struct {
	input    *io.PipeWriter
	output   *io.PipeReader
	messages chan []byte
	done     chan struct{}
	err      error
}

func openModernStdio(t *testing.T, server *Server, initial *auth.Principal, refresh func(context.Context) (*auth.Principal, error)) *stdioPipe {
	t.Helper()
	in, input := io.Pipe()
	output, out := io.Pipe()
	ctx, cancel := context.WithCancel(t.Context())
	pipe := &stdioPipe{input: input, output: output, messages: make(chan []byte, 64), done: make(chan struct{})}
	go func() {
		defer close(pipe.done)
		pipe.err = server.ServeAuthenticatedStdio(ctx, in, out, initial, refresh)
	}()
	go func() {
		scanner := bufio.NewScanner(output)
		scanner.Buffer(make([]byte, 1024), 4<<20)
		defer close(pipe.messages)
		for scanner.Scan() {
			select {
			case pipe.messages <- append([]byte(nil), scanner.Bytes()...):
			case <-ctx.Done():
				return
			}
		}
	}()
	t.Cleanup(func() {
		cancel()
		_ = input.Close()
		_ = output.Close()
		select {
		case <-pipe.done:
		case <-time.After(5 * time.Second):
			t.Error("stdio did not stop after its pipes closed")
		}
	})
	return pipe
}

func (p *stdioPipe) send(t *testing.T, raw []byte) {
	t.Helper()
	done := make(chan error, 1)
	go func() {
		_, err := p.input.Write(append(append([]byte(nil), raw...), '\n'))
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("stdio stopped reading input")
	}
}

func (p *stdioPipe) next(t *testing.T) []byte {
	t.Helper()
	select {
	case raw, ok := <-p.messages:
		if !ok {
			t.Fatal("stdio output closed early")
		}
		if !json.Valid(raw) {
			t.Fatal("concurrent stdio output interleaved JSON messages")
		}
		return raw
	case <-time.After(5 * time.Second):
		t.Fatal("stdio response did not arrive")
		return nil
	}
}

func withModernID(raw []byte, id any) []byte {
	var request map[string]json.RawMessage
	_ = json.Unmarshal(raw, &request)
	request["id"], _ = json.Marshal(id)
	result, _ := json.Marshal(request)
	return result
}

func TestModernStdioCancellationReleasesSourceAndSuppressesLateOutput(t *testing.T) {
	b := &cancelNativeBackend{nativeBackendProbe: &nativeBackendProbe{}, canceled: make(chan struct{}), started: make(chan struct{})}
	var active, releases atomic.Int32
	released := make(chan struct{}, 1)
	s := nativeProbeServer(b, func(context.Context, *auth.Principal) (func(), error) {
		active.Add(1)
		return func() { active.Add(-1); releases.Add(1); released <- struct{}{} }, nil
	})
	WithStdioLimits(StdioLimits{Workers: 1, Queued: 2})(s)
	p := nativePrincipal()
	pipe := openModernStdio(t, s, p, func(context.Context) (*auth.Principal, error) { return p, nil })
	pipe.send(t, progressRequest(t, "owned-progress"))
	if !bytes.Contains(pipe.next(t), []byte("notifications/progress")) {
		t.Fatal("admitted request did not report progress")
	}
	select {
	case <-b.started:
	case <-time.After(5 * time.Second):
		t.Fatal("native query did not start")
	}
	// Numeric aliases refer to the same integer ID without float rounding.
	pipe.send(t, []byte(`{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":10e-1,"reason":"private-untrusted-reason"}}`)) //nolint:misspell // Independent fixture uses MCP's exact wire spelling.
	select {
	case <-b.canceled:
	case <-time.After(5 * time.Second):
		t.Fatal("cancellation did not reach the blocked source")
	}
	select {
	case <-released:
	case <-time.After(5 * time.Second):
		t.Fatal("cancellation retained native admission")
	}
	pipe.send(t, withModernID(modernRequest("ping", nil), 99))
	response := pipe.next(t)
	if !bytes.Contains(response, []byte(`"id":99`)) || bytes.Contains(response, []byte("owned-progress")) || active.Load() != 0 || releases.Load() != 1 {
		t.Fatal("canceled request emitted a late frame or did not release exactly once")
	}
}

func TestModernStdioEOFCancelsBlockedSourceAndExits(t *testing.T) {
	b := &cancelNativeBackend{nativeBackendProbe: &nativeBackendProbe{}, canceled: make(chan struct{}), started: make(chan struct{})}
	s := nativeProbeServer(b, nil)
	p := nativePrincipal()
	pipe := openModernStdio(t, s, p, func(context.Context) (*auth.Principal, error) { return p, nil })
	pipe.send(t, progressRequest(t, "owned-eof"))
	_ = pipe.next(t)
	select {
	case <-b.started:
	case <-time.After(5 * time.Second):
		t.Fatal("source did not start")
	}
	_ = pipe.input.Close()
	select {
	case <-pipe.done:
		if pipe.err != nil {
			t.Fatal(pipe.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("EOF did not stop the modern stream")
	}
	select {
	case <-b.canceled:
	default:
		t.Fatal("stream exited without canceling its source")
	}
}

func TestModernStdioRejectsActiveIDAliasesTokensAndFullQueue(t *testing.T) {
	b := &cancelNativeBackend{nativeBackendProbe: &nativeBackendProbe{}, canceled: make(chan struct{}), started: make(chan struct{})}
	s := nativeProbeServer(b, nil)
	WithStdioLimits(StdioLimits{Workers: 1, Queued: 1})(s)
	p := nativePrincipal()
	pipe := openModernStdio(t, s, p, func(context.Context) (*auth.Principal, error) { return p, nil })
	pipe.send(t, progressRequest(t, json.Number("100e-2")))
	_ = pipe.next(t)
	select {
	case <-b.started:
	case <-time.After(5 * time.Second):
		t.Fatal("source did not start")
	}
	duplicateID := bytes.Replace(progressRequest(t, "different-token"), []byte(`"id":1`), []byte(`"id":1.0`), 1)
	pipe.send(t, duplicateID)
	if raw := pipe.next(t); !bytes.Contains(raw, []byte("already active")) || bytes.Contains(raw, []byte(`"id":1`)) {
		t.Fatal("duplicate ID alias impersonated its active response")
	}
	pipe.send(t, withModernID(progressRequest(t, 1), 2))
	if !bytes.Contains(pipe.next(t), []byte("already active")) {
		t.Fatal("duplicate numeric progress token accepted")
	}
	pipe.send(t, withModernID(modernRequest("ping", nil), 3)) // one queued request
	pipe.send(t, withModernID(modernRequest("ping", nil), 4))
	if raw := pipe.next(t); !bytes.Contains(raw, []byte(`"code":-33003`)) || !bytes.Contains(raw, []byte(`"id":4`)) {
		t.Fatal("full internal queue was not refused")
	}
	pipe.send(t, stdioCancelFrame(json.RawMessage("1")))
	if raw := pipe.next(t); !bytes.Contains(raw, []byte(`"id":3`)) {
		t.Fatal("queue admission blocked reading the cancellation notification")
	}
}

func TestModernStdioInvalidRefreshCancelsActiveAndQueuedRequests(t *testing.T) {
	for _, kind := range []string{"revoked", "tenant", "user", "mutated-anchor"} {
		t.Run(kind, func(t *testing.T) {
			b := &cancelNativeBackend{nativeBackendProbe: &nativeBackendProbe{}, canceled: make(chan struct{}), started: make(chan struct{})}
			s := nativeProbeServer(b, nil)
			WithStdioLimits(StdioLimits{Workers: 1, Queued: 2})(s)
			p := nativePrincipal()
			var invalid atomic.Bool
			var refreshes atomic.Int32
			secondAuthenticated := make(chan struct{})
			refresh := func(context.Context) (*auth.Principal, error) {
				if !invalid.Load() {
					if refreshes.Add(1) == 3 {
						close(secondAuthenticated)
					}
					return p, nil
				}
				current := nativePrincipal()
				switch kind {
				case "revoked":
					return nil, errors.New("private credential failure")
				case "tenant":
					current.TenantID = "sibling-tenant"
				case "user":
					current.UserID = "sibling-user"
				case "mutated-anchor":
					p.TenantID = "mutated-tenant"
					current = p
				}
				return current, nil
			}
			pipe := openModernStdio(t, s, p, refresh)
			pipe.send(t, progressRequest(t, "owned-revocation"))
			_ = pipe.next(t)
			select {
			case <-b.started:
			case <-time.After(5 * time.Second):
				t.Fatal("source did not start")
			}
			pipe.send(t, withModernID(modernRequest("ping", nil), 2))
			select {
			case <-secondAuthenticated:
			case <-time.After(5 * time.Second):
				t.Fatal("second request was not authenticated before revocation")
			}
			invalid.Store(true)
			pipe.send(t, withModernID(modernRequest("tools/list", nil), 3))
			response := pipe.next(t)
			if !bytes.Contains(response, []byte(`"code":-33001`)) || !bytes.Contains(response, []byte(`"id":3`)) || bytes.Contains(response, []byte("private credential")) {
				t.Fatal("invalid refresh exposed data or source error")
			}
			select {
			case <-b.canceled:
			case <-time.After(5 * time.Second):
				t.Fatal("revocation did not stop active work")
			}
		})
	}
}

func TestModernStdioInvalidLimitsRefuseBeforeReading(t *testing.T) {
	for _, limits := range []StdioLimits{{}, {Workers: -1, Queued: 8}, {Workers: 2, Queued: 10001}} {
		s := newTestServer(&fakeBackend{}, testGate(), WithStdioLimits(limits))
		var output bytes.Buffer
		if err := s.ServeStdio(t.Context(), strings.NewReader("not read"), &output, stdioPrincipal()); err == nil || output.Len() != 0 {
			t.Fatal("invalid cost policy read or wrote the stream")
		}
	}
}

func TestModernStdioBlockedStdoutDoesNotRetainQueryAdmission(t *testing.T) {
	b := &cancelNativeBackend{nativeBackendProbe: &nativeBackendProbe{}, canceled: make(chan struct{}), started: make(chan struct{})}
	released := make(chan struct{}, 1)
	s := nativeProbeServer(b, func(context.Context, *auth.Principal) (func(), error) {
		return func() { released <- struct{}{} }, nil
	})
	in, input := io.Pipe()
	output, out := io.Pipe() // deliberately never read: first progress write blocks
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- s.ServeStdio(ctx, in, out, nativePrincipal()) }()
	t.Cleanup(func() { cancel(); _ = input.Close(); _ = output.Close() })
	pipe := &stdioPipe{input: input}
	pipe.send(t, progressRequest(t, "owned-blocked-output"))
	select {
	case <-b.started:
	case <-time.After(5 * time.Second):
		t.Fatal("blocked stdout prevented source execution")
	}
	pipe.send(t, stdioCancelFrame(json.RawMessage("1")))
	select {
	case <-released:
	case <-time.After(5 * time.Second):
		t.Fatal("blocked stdout prevented cancellation from releasing admission")
	}
	_ = input.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("EOF did not interrupt blocked stdout")
	}
}

type queuedStdioBackend struct {
	fakeBackend
	calls   atomic.Int32
	started chan struct{}
	release chan struct{}
}

func (b *queuedStdioBackend) ListTests(ctx context.Context, _ *auth.Principal) (TestsResult, error) {
	if b.calls.Add(1) == 1 {
		close(b.started)
		select {
		case <-b.release:
		case <-ctx.Done():
			return TestsResult{}, ctx.Err()
		}
	}
	return TestsResult{Tests: []TestSummary{{ID: "owned"}}}, nil
}

func TestModernStdioQueuedWorkReloadsPermissionsBeforeSourceRead(t *testing.T) {
	b := &queuedStdioBackend{started: make(chan struct{}), release: make(chan struct{})}
	s := newTestServer(b, testGate(), WithStdioLimits(StdioLimits{Workers: 1, Queued: 2}))
	var refreshes atomic.Int32
	var revoked atomic.Bool
	queued := make(chan struct{})
	refresh := func(context.Context) (*auth.Principal, error) {
		p := stdioPrincipal()
		if revoked.Load() {
			p.Permissions = map[string]bool{}
		}
		if refreshes.Add(1) == 4 {
			close(queued) // third frame: preceding second frame is already queued
		}
		return p, nil
	}
	pipe := openModernStdio(t, s, stdioPrincipal(), refresh)
	request := modernRequest("tools/call", map[string]any{"name": "list_tests", "arguments": map[string]any{}})
	pipe.send(t, request)
	select {
	case <-b.started:
	case <-time.After(5 * time.Second):
		t.Fatal("first source read did not start")
	}
	pipe.send(t, withModernID(request, 2))
	pipe.send(t, withModernID(modernRequest("ping", nil), 3))
	select {
	case <-queued:
	case <-time.After(5 * time.Second):
		t.Fatal("reader did not admit queued work")
	}
	revoked.Store(true)
	close(b.release)
	var second []byte
	for range 3 {
		raw := pipe.next(t)
		if bytes.Contains(raw, []byte(`"id":2`)) {
			second = raw
		}
	}
	if b.calls.Load() != 1 || !bytes.Contains(second, []byte(`"code":-33002`)) {
		t.Fatal("queued request read source using stale permissions")
	}
}

func TestModernStdioCancellationCannotCrossStreamsWithEqualIDs(t *testing.T) {
	var pipes []*stdioPipe
	var backends []*cancelNativeBackend
	for _, tenant := range []string{"owned-blue", "owned-red"} {
		b := &cancelNativeBackend{nativeBackendProbe: &nativeBackendProbe{}, canceled: make(chan struct{}), started: make(chan struct{})}
		p := nativePrincipal()
		p.TenantID = tenant
		pipe := openModernStdio(t, nativeProbeServer(b, nil), p, func(context.Context) (*auth.Principal, error) { return p, nil })
		pipe.send(t, progressRequest(t, 1))
		_ = pipe.next(t)
		select {
		case <-b.started:
		case <-time.After(5 * time.Second):
			t.Fatal("source did not start")
		}
		pipes, backends = append(pipes, pipe), append(backends, b)
	}
	pipes[0].send(t, stdioCancelFrame(json.RawMessage("1")))
	select {
	case <-backends[0].canceled:
	case <-time.After(5 * time.Second):
		t.Fatal("own request was not canceled")
	}
	pipes[1].send(t, withModernID(modernRequest("ping", nil), 2))
	if raw := pipes[1].next(t); !bytes.Contains(raw, []byte(`"id":2`)) {
		t.Fatal("sibling stream lost its independent request")
	}
	select {
	case <-backends[1].canceled:
		t.Fatal("request ID canceled a sibling tenant's stream")
	default:
	}
}

func stdioCancelFrame(id json.RawMessage) []byte {
	raw, _ := json.Marshal(map[string]any{"jsonrpc": jsonRPCVersion, "method": notificationCanceled, "params": map[string]any{"requestId": id}})
	return raw
}

func TestModernStdioRetiresFinalFrameClaimsBeforeClientCanReuse(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	job := &stdioJob{ctx: ctx, cancel: cancel, key: "n:1e0", tokenKey: "s:owned"}
	stream := &stdioStream{ctx: t.Context(), active: map[string]*stdioJob{job.key: job}, tokens: map[string]*stdioJob{job.tokenKey: job}}
	var replacement *stdioJob
	stream.writer = stdioBoundaryWriter{write: func(payload []byte) (int, error) {
		stream.stateMu.Lock()
		defer stream.stateMu.Unlock()
		if replacement == nil {
			if stream.active[job.key] != nil || stream.tokens[job.tokenKey] != nil {
				t.Fatal("final response reached client before releasing ID/token")
			}
			replacement = &stdioJob{key: job.key, tokenKey: job.tokenKey}
			stream.active[job.key], stream.tokens[job.tokenKey] = replacement, replacement
		}
		return len(payload), nil
	}}
	if err := stream.writeJobFrame(stdioOutput{job: job, payload: []byte(`{"jsonrpc":"2.0","id":1,"result":{}}`), done: make(chan error, 1)}); err != nil {
		t.Fatal(err)
	}
	stream.finish(job)
	if stream.active[job.key] != replacement || stream.tokens[job.tokenKey] != replacement {
		t.Fatal("old worker cleanup removed the reused ID/token")
	}
}

type stdioBoundaryWriter struct{ write func([]byte) (int, error) }

func (w stdioBoundaryWriter) Write(payload []byte) (int, error) { return w.write(payload) }

func TestModernStdioClientCanImmediatelyReuseCompletedID(t *testing.T) {
	p := stdioPrincipal()
	pipe := openModernStdio(t, newTestServer(&fakeBackend{}, testGate()), p, func(context.Context) (*auth.Principal, error) { return p, nil })
	for range 32 {
		pipe.send(t, modernRequest("ping", nil))
		if raw := pipe.next(t); bytes.Contains(raw, []byte(`"error"`)) || !bytes.Contains(raw, []byte(`"id":1`)) {
			t.Fatal("completed request ID was still reserved")
		}
	}
}
