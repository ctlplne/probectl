// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package auth

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/crypto"
)

func workerSessionRequest(token string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/v1/explorer/flow/questions", nil)
	r.AddCookie(&http.Cookie{Name: SessionCookie, Value: token})
	return r
}

func TestWorkerOriginSessionUsesExactMatchedHashIncludingLegacy(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		t.Run(fmt.Sprint("legacy=", legacy), func(t *testing.T) {
			st := newFakeStore()
			mgr := NewManager(st, time.Hour, true, bytes.Repeat([]byte{3}, 32))
			token := "owned opaque session from a successful authentication"
			hash := mgr.hashToken(token)
			if legacy {
				hash = legacyHashToken(token)
			}
			poison, _ := CaptureWorkerCredential(WorkerCredentialMCP, workerTenant, workerOwner, workerOther, crypto.Hash([]byte("untrusted store metadata")))
			sess := Session{ID: workerID, TenantID: workerTenant, UserID: workerOwner, AuthorizationHash: PermissionFingerprint([]string{"flow.read"}), workerCredential: poison}
			sess.ExpiresAt = time.Now().Add(time.Hour)
			sess.LastActivityAt = time.Now()
			st.byHash[string(hash)] = sess
			p, err := NewAuthenticator(mgr, fakePerms{keys: []string{"flow.read"}}).Resolve(workerSessionRequest(token))
			if err != nil || p == nil {
				t.Fatal("existing session authentication failed", err)
			}
			ref, err := WorkerCredentialFromPrincipal(p)
			if err != nil || !ref.MatchesStored(WorkerCredentialSession, workerTenant, workerOwner, workerID, hash) {
				t.Fatal("origin did not bind the exact successful session lookup", err)
			}
			if legacy && ref.MatchesStored(WorkerCredentialSession, workerTenant, workerOwner, workerID, mgr.hashToken(token)) {
				t.Fatal("legacy match borrowed an unaccepted keyed credential")
			}
			if p.ViaBearerToken || !p.Has("flow.read") {
				t.Fatal("origin capture changed session authority")
			}
			raw := []byte(token)
			encoded, err := ref.MarshalBinary()
			if err != nil || bytes.Contains(encoded, raw) || bytes.Contains(encoded, hash) {
				t.Fatal("origin retained raw credential", err)
			}
		})
	}
}

func TestWorkerOriginRotationCapturesOnlyThisRequestsAcceptedSuccessor(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		t.Run(fmt.Sprint("legacy=", legacy), func(t *testing.T) {
			st := newFakeStore()
			mgr := NewManager(st, time.Hour, true, bytes.Repeat([]byte{4}, 32))
			token := "owned old session for rotation proof"
			oldHash := mgr.hashToken(token)
			if legacy {
				oldHash = legacyHashToken(token)
			}
			st.byHash[string(oldHash)] = Session{ID: workerID, TenantID: workerTenant, UserID: workerOwner,
				ExpiresAt: time.Now().Add(time.Hour), LastActivityAt: time.Now(), AuthorizationHash: PermissionFingerprint([]string{"flow.read"})}
			before, err := NewAuthenticator(mgr, fakePerms{keys: []string{"flow.read"}}).Resolve(workerSessionRequest(token))
			if err != nil {
				t.Fatal(err)
			}
			oldRef, err := WorkerCredentialFromPrincipal(before)
			if err != nil {
				t.Fatal(err)
			}
			p, replacement, err := NewAuthenticator(mgr, fakePerms{keys: []string{"flow.read", "flow.write"}}).ResolveAndRotate(workerSessionRequest(token))
			if err != nil || p == nil || replacement == "" {
				t.Fatal("rotation did not authenticate", err)
			}
			ref, err := WorkerCredentialFromPrincipal(p)
			replacementHash := mgr.hashToken(replacement)
			if err != nil || !ref.MatchesStored(WorkerCredentialSession, workerTenant, workerOwner, workerID, replacementHash) {
				t.Fatal("rotation kept the predecessor reference", err)
			}
			if oldRef.MatchesStored(WorkerCredentialSession, workerTenant, workerOwner, workerID, replacementHash) || ref.MatchesStored(WorkerCredentialSession, workerTenant, workerOwner, workerID, oldHash) {
				t.Fatal("same-ID rotation borrowed another generation")
			}
			next, err := mgr.Rotate(context.Background(), replacement, st.byHash[string(replacementHash)])
			if err != nil {
				t.Fatal(err)
			}
			if ref.MatchesStored(WorkerCredentialSession, workerTenant, workerOwner, workerID, mgr.hashToken(next)) {
				t.Fatal("captured request borrowed a later concurrent successor")
			}
		})
	}
}

func TestWorkerOriginNoRotationAndMalformedSessionKeepOrdinaryAuthSemantics(t *testing.T) {
	for _, id := range []string{workerID, ""} {
		st := newFakeStore()
		mgr := NewManager(st, time.Hour, true, nil)
		token, err := mgr.Issue(context.Background(), Session{ID: id, TenantID: workerTenant, UserID: workerOwner, AuthorizationHash: PermissionFingerprint([]string{"flow.read"})})
		if err != nil {
			t.Fatal(err)
		}
		p, replacement, err := NewAuthenticator(mgr, fakePerms{keys: []string{"flow.read"}}).ResolveAndRotate(workerSessionRequest(token))
		if err != nil || p == nil || replacement != "" || !p.Has("flow.read") {
			t.Fatal("ordinary unchanged authentication failed", err)
		}
		ref, err := WorkerCredentialFromPrincipal(p)
		if id == "" {
			if !errors.Is(err, ErrWorkerCredentialInvalid) {
				t.Fatal("missing authoritative row ID admitted worker", err)
			}
		} else if err != nil || !ref.MatchesStored(WorkerCredentialSession, workerTenant, workerOwner, id, mgr.hashToken(token)) {
			t.Fatal("unchanged session lost origin", err)
		}
	}
}

type workerLosingRotationStore struct{ *fakeStore }

func (workerLosingRotationStore) RotateByHash(context.Context, []byte, []byte, Session) (bool, error) {
	return false, nil
}

func TestWorkerOriginFailedAuthenticationReturnsNoPrincipal(t *testing.T) {
	st := newFakeStore()
	mgr := NewManager(workerLosingRotationStore{st}, time.Hour, true, nil)
	token, err := mgr.Issue(context.Background(), Session{ID: workerID, TenantID: workerTenant, UserID: workerOwner})
	if err != nil {
		t.Fatal(err)
	}
	p, replacement, err := NewAuthenticator(mgr, fakePerms{keys: []string{"flow.read"}}).ResolveAndRotate(workerSessionRequest(token))
	if !errors.Is(err, ErrSessionNotFound) || p != nil || replacement != "" {
		t.Fatal("lost rotation admitted a worker principal", err)
	}
	p, err = NewAuthenticator(mgr, fakePerms{err: errors.New("owned permission backend failure")}).Resolve(workerSessionRequest(token))
	if err == nil || p != nil {
		t.Fatal("permission error admitted an origin principal")
	}
}

func TestWorkerOriginAttachmentPreservesIdentityAndBearerBoundary(t *testing.T) {
	session, hash := workerTestReference(t, WorkerCredentialSession)
	bearer, _ := workerTestReference(t, WorkerCredentialMCP)
	p := &Principal{TenantID: workerTenant, UserID: workerOwner, Permissions: map[string]bool{"flow.read": true}}
	attached, err := WithWorkerCredential(p, bearer)
	if err != nil || attached == p || !attached.ViaBearerToken || !attached.Has("flow.read") || p.ViaBearerToken {
		t.Fatal("MCP binding did not preserve a copied bearer principal", err)
	}
	if _, err := WorkerCredentialFromPrincipal(p); !errors.Is(err, ErrWorkerCredentialInvalid) {
		t.Fatal("capture mutated input principal", err)
	}
	if _, err := WithWorkerCredential(attached, session); !errors.Is(err, ErrWorkerCredentialInvalid) {
		t.Fatal("session attachment erased bearer provenance", err)
	}
	for _, foreign := range []*Principal{nil, {TenantID: workerOther, UserID: workerOwner}, {TenantID: workerTenant, UserID: workerOther}} {
		if _, err := WithWorkerCredential(foreign, session); !errors.Is(err, ErrWorkerCredentialInvalid) {
			t.Fatal("foreign principal accepted origin", err)
		}
	}
	copied, err := WithWorkerCredential(p, session)
	if err != nil {
		t.Fatal(err)
	}
	copied.TenantID = workerOther
	if _, err := WorkerCredentialFromPrincipal(copied); !errors.Is(err, ErrWorkerCredentialInvalid) {
		t.Fatal("mutated principal reused captured scope", err)
	}
	copied, err = WithWorkerCredential(p, session)
	if err != nil {
		t.Fatal(err)
	}
	copied.ViaBearerToken = true
	if _, err := WorkerCredentialFromPrincipal(copied); !errors.Is(err, ErrWorkerCredentialInvalid) {
		t.Fatal("origin kind mismatch accepted", err)
	}
	ref, err := WorkerCredentialFromPrincipal(attached)
	if err != nil || !ref.MatchesStored(WorkerCredentialMCP, workerTenant, workerOwner, workerID, hash) {
		t.Fatal("exact bearer binding lost", err)
	}
}

func TestWorkerOriginSessionAndPrincipalNeverSerializePrivateBinding(t *testing.T) {
	ref, hash := workerTestReference(t, WorkerCredentialSession)
	p, err := WithWorkerCredential(&Principal{TenantID: workerTenant, UserID: workerOwner}, ref)
	if err != nil {
		t.Fatal(err)
	}
	sess := Session{TenantID: workerTenant, UserID: workerOwner, workerCredential: ref}
	for _, value := range []any{p, *p, &sess, sess, struct{ private Principal }{*p}, struct{ private Session }{sess}} {
		encoded, err := json.Marshal(value)
		if err != nil {
			t.Fatal("ordinary public serialization failed", err)
		}
		rendered := string(encoded) + fmt.Sprintf("%v %+v %#v", value, value, value)
		for _, private := range []string{workerID, hex.EncodeToString(hash), hex.EncodeToString(ref.binding.fingerprint[:])} {
			if strings.Contains(rendered, private) {
				t.Fatal("principal/session serialization disclosed private credential metadata")
			}
		}
	}
}
