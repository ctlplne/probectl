// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package mcp

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
)

func TestHTTPAuthenticationUnavailableIsRetryableWithoutPrivateText(t *testing.T) {
	for _, tc := range []struct {
		name   string
		err    error
		status int
	}{
		{"unavailable", apierror.Unavailable("private lifecycle database diagnostic"), http.StatusServiceUnavailable},
		{"bad credential", errors.New("private credential database diagnostic"), http.StatusUnauthorized},
		{"policy refusal", ErrForbidden, http.StatusForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			backend := &fakeBackend{}
			var logs bytes.Buffer
			server := newTestServer(backend, testGate(), WithLogger(slog.New(slog.NewTextHandler(&logs, nil))))
			socket := httptest.NewTLSServer(server.HTTPHandler(fakeAuthn{err: tc.err}))
			defer socket.Close()
			response := legacyTLSCall(t, socket, []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`), "owned-token", "")
			defer response.Body.Close()
			raw, err := io.ReadAll(response.Body)
			if err != nil {
				t.Fatal(err)
			}
			if response.StatusCode != tc.status || len(backend.seen()) != 0 || strings.Contains(string(raw)+logs.String(), "private") {
				t.Fatal("authentication refusal lost classification, called a source or copied a diagnostic", response.StatusCode)
			}
			if (response.Header.Get("WWW-Authenticate") != "") != (tc.status == http.StatusUnauthorized) {
				t.Fatal("temporary policy outage was classified as an invalid credential")
			}
		})
	}
}

func TestStdioAuthenticationUnavailableRefusesAllWireEras(t *testing.T) {
	for _, wire := range []string{protocolVersion, legacyProtocolVersion, modernProtocolVersion} {
		t.Run(wire, func(t *testing.T) {
			backend := &fakeBackend{}
			server := newTestServer(backend, testGate())
			pipe := openModernStdio(t, server, stdioPrincipal(), func(context.Context) (*auth.Principal, error) {
				return nil, apierror.Unavailable("private lifecycle database diagnostic")
			})
			frame := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
			want := codeUnavailable
			switch wire {
			case legacyProtocolVersion:
				frame = legacy2025Initialize()
				want = codeModernUnavailable
			case modernProtocolVersion:
				frame = modernRequest("tools/list", nil)
				want = codeModernUnavailable
			}
			pipe.send(t, frame)
			response := pipe.next(t)
			if rpcErrorCode(response) != want || bytes.Contains(response, []byte("private")) || len(backend.seen()) != 0 {
				t.Fatal("stdio unavailable policy leaked source data or private errors", string(response))
			}
		})
	}
}
