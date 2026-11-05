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
	"sync"

	"github.com/ctlplne/probectl/internal/auth"
)

type stdioJob struct {
	req      rpcRequest
	raw      []byte
	key      string
	tokenKey string
	ctx      context.Context
	cancel   context.CancelFunc
}

const notificationCanceled = "notifications/cancelled" //nolint:misspell // MCP defines this exact wire spelling.

type stdioOutput struct {
	job     *stdioJob
	payload []byte
	done    chan error
}

// Reader, fixed workers and one bounded control writer have separate roles:
// a slow stdout must not prevent stdin from observing cancellation. No input
// frame creates a goroutine or an unbounded pending response.
type stdioStream struct {
	server       *Server
	ctx          context.Context
	cancel       context.CancelFunc
	writer       io.Writer
	initial      *auth.Principal
	tenant, user string
	refresh      func(context.Context) (*auth.Principal, error)
	authMu       sync.Mutex
	stateMu      sync.Mutex
	active       map[string]*stdioJob
	tokens       map[string]*stdioJob
	jobs         chan *stdioJob
	control      chan []byte
	output       chan stdioOutput
	workers      sync.WaitGroup
	errMu        sync.Mutex
	err          error
	legacy       bool
	initializing bool
	initialized  bool
	ready        bool
}

func (s *Server) serveVersionedStdio(ctx context.Context, scanner *bufio.Scanner, first []byte, reader io.Reader, writer io.Writer, initial *auth.Principal, tenant, user string, refresh func(context.Context) (*auth.Principal, error)) error {
	runCtx, cancel := context.WithCancel(ctx)
	stream := &stdioStream{server: s, ctx: runCtx, cancel: cancel, writer: writer, initial: initial, tenant: tenant, user: user, refresh: refresh,
		active: map[string]*stdioJob{}, tokens: map[string]*stdioJob{}, jobs: make(chan *stdioJob, s.stdioLimits.Queued), control: make(chan []byte, s.stdioLimits.Queued), output: make(chan stdioOutput, 2*s.stdioLimits.Workers)}
	firstRequest, _ := s.decodeRPC(first, false)
	stream.legacy = firstRequest.protocol.version == legacyProtocolVersion && !firstRequest.protocol.modern
	closed := make(chan struct{})
	context.AfterFunc(runCtx, func() {
		stream.cancelAll()
		// Shipping stdin/stdout are closable OS streams. Custom blocking IO
		// must implement Close, or its caller must unblock it on cancellation.
		if closer, ok := reader.(io.Closer); ok {
			_ = closer.Close()
		}
		if closer, ok := writer.(io.Closer); ok {
			_ = closer.Close()
		}
		close(closed)
	})
	for range s.stdioLimits.Workers {
		stream.workers.Go(stream.work)
	}
	stream.workers.Go(stream.writeOutput)
	stream.receive(first)
	for runCtx.Err() == nil && scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) != 0 {
			stream.receive(line)
		}
	}
	if err := scanner.Err(); err != nil {
		stream.fail(err)
	}
	cancel()
	<-closed
	stream.workers.Wait()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return stream.err
}

func (s *stdioStream) fail(err error) {
	s.errMu.Lock()
	if s.err == nil && s.ctx.Err() == nil {
		s.err = err
	}
	s.errMu.Unlock()
	s.cancel()
}

func (s *stdioStream) current(ctx context.Context) (*auth.Principal, error) {
	s.authMu.Lock()
	defer s.authMu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	p := s.initial
	var err error
	if s.refresh != nil {
		p, err = s.refresh(ctx)
	}
	if err != nil {
		return nil, err
	}
	if p == nil || p.TenantID == "" || p.TenantID != s.tenant || p.UserID != s.user {
		return nil, errors.New("mcp: stdio identity is no longer authorized")
	}
	// A refresher can reuse its principal object. Executing jobs receive their
	// own grants snapshot, never an object mutated by a subsequent refresh.
	return principalSnapshot(p), nil
}

func (s *stdioStream) receive(raw []byte) {
	req, failure := s.server.decodeRPC(raw, false)
	if !req.protocol.modern {
		if s.legacy || req.protocol.version == legacyProtocolVersion {
			req, failure = decodeLegacy2025RPCBudget(raw, s.server.nativeRequestBytes())
		} else {
			req, failure = s.server.decodeRPC(raw, true)
		}
	}
	_, authErr := s.current(s.ctx)
	notification, cancelKey := stdioNotification(raw)
	if authErr != nil {
		s.cancelAll()
		if !notification {
			if _, valid := requestIDKey(req.ID); valid {
				s.enqueueControl(s.server.prepareResponse(req, stdioAuthFailure(req.ID, authErr)))
			}
		}
		return
	}
	if notification {
		if s.legacy && initializedNotification(raw) {
			s.stateMu.Lock()
			s.ready = s.initialized
			s.stateMu.Unlock()
		}
		if cancelKey != "" {
			s.stateMu.Lock()
			if job := s.active[cancelKey]; job != nil {
				if job.req.protocol.modern || job.req.Method != "initialize" {
					job.cancel()
				}
			}
			s.stateMu.Unlock()
		}
		return
	}
	if failure != nil {
		s.enqueueControl(s.server.prepareResponse(req, failure))
		return
	}
	if !req.protocol.modern && req.protocol.version == legacyProtocolVersion && req.Method == "initialize" {
		s.legacy = true // authenticated explicit legacy selection after a modern probe is valid
	}
	if !req.protocol.modern && req.protocol.version == legacyProtocolVersion && !s.admitLegacy(req) {
		s.enqueueControl(errorResponse(req.ID, codeInvalidRequest, "legacy initialization is incomplete or already started"))
		return
	}
	s.enqueueJob(req, raw)
}

func (s *stdioStream) admitLegacy(req rpcRequest) bool {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	if req.Method == "initialize" {
		if s.initializing || s.initialized {
			return false
		}
		s.initializing = true
		return true
	}
	return req.Method == "ping" || s.ready
}

func initializedNotification(raw []byte) bool {
	var root map[string]json.RawMessage
	var method string
	return boundedJSONObjectSyntax(raw, 4<<20, false) == nil && json.Unmarshal(raw, &root) == nil && len(root["id"]) == 0 && json.Unmarshal(root["method"], &method) == nil && method == "notifications/initialized"
}

func stdioAuthFailure(id json.RawMessage, err error) *rpcResponse {
	code, message := codeUnauthorized, "credential is invalid or no longer authorized"
	if errors.Is(err, ErrForbidden) {
		code, message = codeForbidden, "credential is forbidden by current policy"
	} else if authenticationUnavailable(err) {
		code, message = codeUnavailable, "authentication policy is temporarily unavailable"
	}
	return errorResponse(id, code, message)
}

// Malformed/unknown notifications have no response and cannot cancel anything.
// Metadata and the optional reason are never used as authority or logged.
func stdioNotification(raw []byte) (bool, string) {
	var root map[string]json.RawMessage
	if json.Unmarshal(raw, &root) != nil {
		return false, ""
	}
	var version, method string
	if json.Unmarshal(root["jsonrpc"], &version) != nil || version != jsonRPCVersion || json.Unmarshal(root["method"], &method) != nil || len(root["id"]) != 0 || method == "" {
		return false, ""
	}
	if method != notificationCanceled || boundedJSONObjectSyntax(raw, 4<<20, false) != nil {
		return true, ""
	}
	var params map[string]json.RawMessage
	if json.Unmarshal(root["params"], &params) != nil || params == nil {
		return true, ""
	}
	if reason, present := params["reason"]; present {
		var text *string
		if json.Unmarshal(reason, &text) != nil || text == nil {
			return true, ""
		}
	}
	key, _ := requestIDKey(params["requestId"])
	return true, key
}

func (s *stdioStream) enqueueControl(response *rpcResponse) {
	select {
	case s.control <- marshal(response):
	case <-s.ctx.Done():
	default:
		// Bounded error delivery cannot stop the input reader or silently
		// accumulate responses behind a client that does not read stdout.
		s.fail(errors.New("mcp: stdio control response queue is full"))
	}
}

func (s *stdioStream) enqueueJob(req rpcRequest, raw []byte) {
	key, _ := requestIDKey(req.ID)
	token, _ := requestIDKey(req.protocol.progress)
	ctx, cancel := context.WithCancel(s.ctx)
	req.protocol.frameReserve = 1 // final newline participates in wire admission
	job := &stdioJob{req: req, raw: append([]byte(nil), raw...), key: key, tokenKey: token, ctx: ctx, cancel: cancel}
	s.stateMu.Lock()
	duplicateID, duplicateToken := s.active[key] != nil, token != "" && s.tokens[token] != nil
	if !duplicateID && !duplicateToken {
		s.active[key] = job
		if token != "" {
			s.tokens[token] = job
		}
	}
	s.stateMu.Unlock()
	if duplicateID || duplicateToken {
		s.finish(job)
		id := req.ID
		if duplicateID {
			id = nil // do not impersonate the original in-flight response
		}
		s.enqueueControl(s.server.prepareResponse(req, errorResponse(id, codeInvalidRequest, "request id or progress token is already active")))
		return
	}
	select {
	case s.jobs <- job:
	case <-s.ctx.Done():
		s.finish(job)
	default:
		s.finish(job)
		s.enqueueControl(s.server.prepareResponse(req, errorResponse(req.ID, codeRateLimited, "stdio request queue is full")))
	}
}

func (s *stdioStream) cancelAll() {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	for _, job := range s.active {
		job.cancel()
	}
}

func (s *stdioStream) finish(job *stdioJob) {
	job.cancel()
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	if !job.req.protocol.modern && job.req.Method == "initialize" && !s.initialized {
		s.initializing = false
	}
	s.retireLocked(job)
}

func (s *stdioStream) retireLocked(job *stdioJob) {
	if s.active[job.key] == job {
		delete(s.active, job.key)
	}
	if job.tokenKey != "" && s.tokens[job.tokenKey] == job {
		delete(s.tokens, job.tokenKey)
	}
}

func (s *stdioStream) work() {
	for {
		select {
		case <-s.ctx.Done():
			return
		case job := <-s.jobs:
			s.execute(job)
		}
	}
}

func (s *stdioStream) execute(job *stdioJob) {
	defer s.finish(job)
	if job.ctx.Err() != nil {
		return
	}
	p, err := s.current(job.ctx)
	if err != nil {
		s.cancelAll()
		return
	}
	ctx := job.ctx
	if len(job.req.protocol.progress) > 0 {
		ctx = withProgressEmitter(ctx, func(stage int) error {
			message, err := progressMessage(job.req.protocol.progress, stage)
			if err != nil {
				return err
			}
			select {
			case s.output <- stdioOutput{job: job, payload: message}:
				return nil
			case <-job.ctx.Done():
				return job.ctx.Err()
			default:
				return errors.New("mcp: stdio progress output queue is full")
			}
		})
	}
	response := s.server.handleRequest(ctx, p, job.req, job.raw)
	if response != nil && job.ctx.Err() == nil {
		// A queued request refreshes before source reads; a finished request
		// also refreshes before output. Neither inherits stale stream grants.
		if _, err := s.current(job.ctx); err != nil {
			s.cancelAll()
			return
		}
		done := make(chan error, 1)
		select {
		case s.output <- stdioOutput{job: job, payload: response, done: done}:
			select {
			case <-done:
			case <-job.ctx.Done():
			}
		case <-job.ctx.Done():
		}
	}
}

func (s *stdioStream) writeOutput() {
	for {
		select {
		case <-s.ctx.Done():
			return
		case response := <-s.control:
			_ = s.write(s.ctx, response)
		case frame := <-s.output:
			err := s.writeJobFrame(frame)
			if frame.done != nil {
				frame.done <- err
			}
		}
	}
}

func (s *stdioStream) writeJobFrame(frame stdioOutput) error {
	s.stateMu.Lock()
	if err := frame.job.ctx.Err(); err != nil {
		s.stateMu.Unlock()
		return err
	}
	if frame.done != nil {
		// This final frame is now committed to the serialized output. A client
		// may reuse its ID as soon as it receives it, before worker cleanup runs.
		s.retireLocked(frame.job)
		if !frame.job.req.protocol.modern && frame.job.req.protocol.version == legacyProtocolVersion && frame.job.req.Method == "initialize" {
			s.initialized = true
			s.initializing = false
		}
	}
	s.stateMu.Unlock()
	return s.writeCommitted(frame.payload)
}

func (s *stdioStream) write(ctx context.Context, payload []byte) error {
	// This is the output commitment point. Cancellation never waits for
	// stdout; a frame already being written may be in flight, but no new
	// frame begins after its cancellation has been observed.
	if err := ctx.Err(); err != nil {
		return err
	}
	return s.writeCommitted(payload)
}

func (s *stdioStream) writeCommitted(payload []byte) error {
	for _, part := range [][]byte{payload, {'\n'}} {
		n, err := s.writer.Write(part)
		if err == nil && n != len(part) {
			err = io.ErrShortWrite
		}
		if err != nil {
			s.fail(err)
			return err
		}
	}
	return nil
}
