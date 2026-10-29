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
	"testing"

	"github.com/ctlplne/probectl/internal/auth"
)

type stdioCountingBackend struct {
	fakeBackend
	calls  int
	onCall func()
}

func (b *stdioCountingBackend) ListTests(context.Context, *auth.Principal) (TestsResult, error) {
	b.calls++
	if b.onCall != nil {
		b.onCall()
	}
	return TestsResult{Tests: []TestSummary{{ID: "owned"}}}, nil
}
func stdioPrincipal() *auth.Principal {
	return &auth.Principal{TenantID: "stdio-owned", UserID: "stdio-user", Permissions: map[string]bool{"test.read": true}}
}

// Assertion-before adapter: the old fixed-principal transport remains callable
// until the authenticated variant is implemented, and reproduces a stale grant.
func TestAuthenticatedStdioRejectsRevocationWithinOneSession(t *testing.T) {
	b := &stdioCountingBackend{}
	revoked := false
	b.onCall = func() { revoked = true }
	server := newTestServer(b, testGate())
	p := stdioPrincipal()
	refresh := func(context.Context) (*auth.Principal, error) {
		if revoked {
			return nil, errors.New("fixture credential revoked")
		}
		return p, nil
	}
	frame := append([]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_tests","arguments":{}}}`), '\n')
	input := bytes.NewReader(append(append([]byte{}, frame...), frame...))
	var output bytes.Buffer
	var err error
	if authenticated, ok := any(server).(interface {
		ServeAuthenticatedStdio(context.Context, io.Reader, io.Writer, *auth.Principal, func(context.Context) (*auth.Principal, error)) error
	}); ok {
		err = authenticated.ServeAuthenticatedStdio(t.Context(), input, &output, p, refresh)
	} else {
		err = server.ServeStdio(t.Context(), input, &output, p)
	}
	if err != nil {
		t.Fatal(err)
	}
	if b.calls != 1 {
		t.Fatalf("stdio reused revoked principal for %d source calls; want1", b.calls)
	}
	lines := bytes.Split(bytes.TrimSpace(output.Bytes()), []byte{'\n'})
	if len(lines) != 2 || !bytes.Contains(lines[1], []byte(`"error"`)) {
		t.Fatal("revoked stdio request did not fail closed in same process")
	}
}

func TestAuthenticatedStdioBindsIdentityAndReloadsPermissions(t *testing.T) {
	for _, kind := range []string{"tenant", "user", "permissions", "mutated-anchor"} {
		t.Run(kind, func(t *testing.T) {
			b := &stdioCountingBackend{}
			server := newTestServer(b, testGate())
			initial := stdioPrincipal()
			calls := 0
			refresh := func(context.Context) (*auth.Principal, error) {
				calls++
				p := stdioPrincipal()
				if calls > 1 {
					switch kind {
					case "tenant":
						p.TenantID = "foreign"
					case "user":
						p.UserID = "foreign"
					case "permissions":
						p.Permissions = map[string]bool{}
					case "mutated-anchor":
						initial.TenantID = "foreign"
						p = initial
					}
				}
				return p, nil
			}
			frame := append([]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_tests","arguments":{}}}`), '\n')
			var output bytes.Buffer
			if err := server.ServeAuthenticatedStdio(t.Context(), bytes.NewReader(append(append([]byte{}, frame...), frame...)), &output, initial, refresh); err != nil {
				t.Fatal(err)
			}
			if b.calls != 1 || calls != 2 {
				t.Fatal("stdio accepted changed identity or stale permissions")
			}
		})
	}
}

func TestAuthenticatedStdioNeverFallsBackWhenRefreshIsMissing(t *testing.T) {
	server := newTestServer(&stdioCountingBackend{}, testGate())
	var output bytes.Buffer
	if err := server.ServeAuthenticatedStdio(t.Context(), bytes.NewReader(nil), &output, stdioPrincipal(), nil); err == nil {
		t.Fatal("authenticated entrypoint allowed a missing refresher")
	}
	if err := server.ServeStdio(t.Context(), bytes.NewReader(nil), &output, stdioPrincipal(), nil); err == nil {
		t.Fatal("shared transport fell back from explicit nil refresher to fixed grants")
	}
	if output.Len() != 0 {
		t.Fatal("invalid authenticated transport wrote a response")
	}
}
