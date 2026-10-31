// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/auth"
)

func legacy2025Request(method string, id any, params map[string]any) []byte {
	raw, _ := json.Marshal(map[string]any{"jsonrpc": jsonRPCVersion, "id": id, "method": method, "params": params})
	return raw
}

func legacy2025Initialize() []byte {
	return legacy2025Request("initialize", 1, map[string]any{"protocolVersion": legacyProtocolVersion, "capabilities": map[string]any{}, "clientInfo": map[string]any{"name": "owned-legacy-fixture", "version": "1"}})
}

func initializeLegacyPipe(t *testing.T, pipe *stdioPipe) {
	t.Helper()
	pipe.send(t, legacy2025Initialize())
	raw := pipe.next(t)
	if rpcErrorCode(raw) != 0 || !bytes.Contains(raw, []byte(`"protocolVersion":"2025-11-25"`)) || bytes.Contains(raw, []byte("resultType")) {
		t.Fatal("explicit legacy initialization did not negotiate its own shape")
	}
	pipe.send(t, []byte(`{"jsonrpc":"2.0","method":"notifications/initialized"}`))
}

func TestLegacy2025StdioRequiresInitializedWithoutChangingModernContext(t *testing.T) {
	p := nativePrincipal()
	pipe := openModernStdio(t, nativeProbeServer(&nativeBackendProbe{}, nil), p, func(context.Context) (*auth.Principal, error) { return p, nil })
	pipe.send(t, legacy2025Initialize())
	if raw := pipe.next(t); rpcErrorCode(raw) != 0 || !bytes.Contains(raw, []byte(`"protocolVersion":"2025-11-25"`)) || bytes.Contains(raw, []byte("resultType")) {
		t.Fatal("initialize did not echo supported legacy version")
	}
	pipe.send(t, legacy2025Request("tools/list", 2, map[string]any{}))
	if raw := pipe.next(t); rpcErrorCode(raw) != codeInvalidRequest {
		t.Fatal("legacy tool discovery preceded initialized notification")
	}
	pipe.send(t, legacy2025Request("ping", 3, map[string]any{}))
	if raw := pipe.next(t); rpcErrorCode(raw) != 0 || bytes.Contains(raw, []byte("resultType")) {
		t.Fatal("legacy ping before initialized failed or changed shape")
	}
	// Modern metadata supplies its own context even before legacy readiness.
	pipe.send(t, withModernID(modernRequest("server/discover", nil), 4))
	if raw := pipe.next(t); rpcErrorCode(raw) != 0 || !bytes.Contains(raw, []byte(`"resultType":"complete"`)) {
		t.Fatal("legacy handshake leaked into independent modern request")
	}
	pipe.send(t, []byte(`{"jsonrpc":"2.0","method":"notifications/initialized"}`))
	pipe.send(t, legacy2025Request("tools/list", 5, map[string]any{}))
	if raw := pipe.next(t); rpcErrorCode(raw) != 0 || !bytes.Contains(raw, []byte("flow_explorer_query")) || bytes.Contains(raw, []byte("resultType")) {
		t.Fatal("initialized legacy process lost native tools or inherited modern shape")
	}
	pipe.send(t, withModernID(modernRequest("ping", nil), 6))
	if raw := pipe.next(t); rpcErrorCode(raw) != 0 || !bytes.Contains(raw, []byte(`"resultType":"complete"`)) {
		t.Fatal("interleaved modern request inherited legacy shape")
	}
	pipe.send(t, withModernID(legacy2025Initialize(), 7))
	if raw := pipe.next(t); rpcErrorCode(raw) != codeInvalidRequest {
		t.Fatal("same legacy process reinitialized established context")
	}
}

func TestLegacy2025InitializeRequiredFieldsAndExactNames(t *testing.T) {
	for _, key := range []string{"protocolVersion", "capabilities", "clientInfo"} {
		var root map[string]json.RawMessage
		_ = json.Unmarshal(legacy2025Initialize(), &root)
		var params map[string]json.RawMessage
		_ = json.Unmarshal(root["params"], &params)
		delete(params, key)
		root["params"], _ = json.Marshal(params)
		raw, _ := json.Marshal(root)
		if _, failure := decodeLegacy2025RPC(raw); failure == nil || failure.Error.Code != codeInvalidParams {
			t.Fatal("legacy initialization accepted missing required field", key)
		}
	}
	raw := bytes.Replace(legacy2025Initialize(), []byte(`"name":`), []byte(`"Name":`), 1)
	if _, failure := decodeLegacy2025RPC(raw); failure == nil || failure.Error.Code != codeInvalidParams {
		t.Fatal("legacy initialize accepted clientInfo case alias")
	}
}

func TestLegacy2025StdioCancellationReleasesAdmissionAndStopsProgress(t *testing.T) {
	b := &cancelNativeBackend{nativeBackendProbe: &nativeBackendProbe{}, started: make(chan struct{}), canceled: make(chan struct{})}
	released := make(chan struct{}, 1)
	s := nativeProbeServer(b, func(context.Context, *auth.Principal) (func(), error) { return func() { released <- struct{}{} }, nil })
	p := nativePrincipal()
	pipe := openModernStdio(t, s, p, func(context.Context) (*auth.Principal, error) { return p, nil })
	initializeLegacyPipe(t, pipe)
	query := legacy2025Request("tools/call", 2, map[string]any{"name": "flow_explorer_query", "arguments": map[string]any{"plan": map[string]any{}}, "_meta": map[string]any{"progressToken": "owned-legacy-progress"}})
	pipe.send(t, query)
	if raw := pipe.next(t); !bytes.Contains(raw, []byte("notifications/progress")) || !bytes.Contains(raw, []byte("owned-legacy-progress")) {
		t.Fatal("legacy query lost its progress token")
	}
	select {
	case <-b.started:
	case <-time.After(5 * time.Second):
		t.Fatal("legacy source did not start")
	}
	pipe.send(t, stdioCancelFrame(json.RawMessage("2.0")))
	select {
	case <-released:
	case <-time.After(5 * time.Second):
		t.Fatal("legacy cancellation retained query admission")
	}
	pipe.send(t, legacy2025Request("ping", 3, map[string]any{}))
	if raw := pipe.next(t); rpcErrorCode(raw) != 0 || !bytes.Contains(raw, []byte(`"id":3`)) || bytes.Contains(raw, []byte("owned-legacy-progress")) {
		t.Fatal("legacy canceled query emitted a later frame")
	}
}

func TestLegacy2025StdioCannotCancelInitialize(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	p := stdioPrincipal()
	key, _ := requestIDKey(json.RawMessage("1"))
	job := &stdioJob{ctx: ctx, cancel: cancel, req: rpcRequest{Method: "initialize", protocol: requestProtocol{version: legacyProtocolVersion}}}
	stream := &stdioStream{server: newTestServer(&fakeBackend{}, testGate()), ctx: t.Context(), initial: p, tenant: p.TenantID, user: p.UserID, legacy: true, active: map[string]*stdioJob{key: job}}
	stream.receive(stdioCancelFrame(json.RawMessage("1")))
	if ctx.Err() != nil {
		t.Fatal("legacy initialization was canceled")
	}
	job.req.Method = "tools/call"
	stream.receive(stdioCancelFrame(json.RawMessage("1")))
	if ctx.Err() == nil {
		t.Fatal("positive control failed to cancel an ordinary legacy request")
	}
}

func TestLegacy2025StdioRechecksCredentialAfterHandshake(t *testing.T) {
	p := nativePrincipal()
	var revoked atomic.Bool
	pipe := openModernStdio(t, nativeProbeServer(&nativeBackendProbe{}, nil), p, func(context.Context) (*auth.Principal, error) {
		if revoked.Load() {
			return nil, errors.New("private credential detail")
		}
		return p, nil
	})
	initializeLegacyPipe(t, pipe)
	pipe.send(t, legacy2025Request("tools/list", 2, map[string]any{}))
	if raw := pipe.next(t); rpcErrorCode(raw) != 0 || !bytes.Contains(raw, []byte("flow_explorer_query")) {
		t.Fatal("legacy valid credential lost native discovery")
	}
	revoked.Store(true)
	pipe.send(t, legacy2025Request("tools/list", 3, map[string]any{}))
	if raw := pipe.next(t); rpcErrorCode(raw) != codeModernUnauthorized || bytes.Contains(raw, []byte("flow_explorer_query")) || bytes.Contains(raw, []byte("private credential")) {
		t.Fatal("legacy transport reused its handshake's credential or leaked private error")
	}
}

func TestLegacy2025StdioCanSelectLegacyAfterModernDiscoveryProbe(t *testing.T) {
	p := nativePrincipal()
	pipe := openModernStdio(t, nativeProbeServer(&nativeBackendProbe{}, nil), p, func(context.Context) (*auth.Principal, error) { return p, nil })
	pipe.send(t, modernRequest("server/discover", nil))
	if raw := pipe.next(t); rpcErrorCode(raw) != 0 || !bytes.Contains(raw, []byte(legacyProtocolVersion)) {
		t.Fatal("modern probe omitted implemented legacy version")
	}
	initializeLegacyPipe(t, pipe)
	pipe.send(t, legacy2025Request("tools/list", 2, map[string]any{}))
	if raw := pipe.next(t); rpcErrorCode(raw) != 0 || bytes.Contains(raw, []byte("resultType")) || !bytes.Contains(raw, []byte("flow_explorer_query")) {
		t.Fatal("modern discovery prevented later explicit legacy selection")
	}
}
