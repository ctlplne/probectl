// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flowconversation

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/tenantcrypto"
)

type messageCodecFixture struct {
	codec        *Codec
	scope        MessageScope
	origin       auth.WorkerCredentialRef
	credentialID string
	storedHash   []byte
	context      context.Context
	key          string
	sealer       *tenantcrypto.EnvelopeSealer
}

func newMessageCodecFixture(t *testing.T) messageCodecFixture {
	t.Helper()
	ids := make([]string, 5)
	for i := range ids {
		var err error
		ids[i], err = crypto.UUIDv4()
		if err != nil {
			t.Fatal(err)
		}
	}
	key, err := crypto.Random(32)
	if err != nil {
		t.Fatal(err)
	}
	f := messageCodecFixture{scope: MessageScope{TenantID: ids[0], OwnerID: ids[1], ConversationID: ids[2], MessageID: ids[3], Revision: 1, Epoch: 1}, credentialID: ids[4], key: base64.StdEncoding.EncodeToString(key)}
	clear(key)
	f.sealer, err = tenantcrypto.NewEnvelopeSealer("owned-history-test", f.key)
	if err != nil {
		t.Fatal(err)
	}
	tenantcrypto.SetPrimary(f.sealer)
	t.Cleanup(tenantcrypto.Reset)
	f.storedHash, err = crypto.Random(32)
	if err != nil {
		t.Fatal(err)
	}
	f.origin, err = auth.CaptureWorkerCredential(auth.WorkerCredentialMCP, f.scope.TenantID, f.scope.OwnerID, f.credentialID, f.storedHash)
	if err != nil {
		t.Fatal(err)
	}
	f.codec, err = NewCodec(DefaultCodecBudget())
	if err != nil {
		t.Fatal(err)
	}
	f.context = tenancy.WithTenant(t.Context(), tenancy.ID(f.scope.TenantID))
	return f
}

func (f messageCodecFixture) authorize(_ context.Context, scope MessageScope, origin auth.WorkerCredentialRef, requirements []string) error {
	if scope != f.scope || !origin.MatchesStored(auth.WorkerCredentialMCP, scope.TenantID, scope.OwnerID, f.credentialID, f.storedHash) || !slices.Equal(requirements, []string{"ai.query", "flow.read", "metrics.read"}) {
		return ErrMessageDenied
	}
	return nil
}

func (f messageCodecFixture) seal(t *testing.T, body []byte) SealedMessage {
	t.Helper()
	sealed, err := f.codec.Seal(f.context, f.scope, f.origin, []string{"metrics.read", "flow.read", "ai.query", "flow.read"}, body)
	if err != nil {
		t.Fatal(err)
	}
	return sealed
}

func TestMessageCodecExactCryptoRoundTripAndImmutablePrivateHeader(t *testing.T) {
	f := newMessageCodecFixture(t)
	body := []byte(`{"question":"bob@example.test over 401 days","number":18446744073709551617,"history":"` + strings.Repeat("source ", 170000) + `","unicode":"\ud83d\ude00"}`)
	original := bytes.Clone(body)
	requirements := []string{"metrics.read", "flow.read", "ai.query", "flow.read"}
	record, err := f.codec.Seal(f.context, f.scope, f.origin, requirements, body)
	if err != nil {
		t.Fatal(err)
	}
	clear(body)
	clear(requirements)
	if strings.Contains(record.parts.header, "bob@example.test") || strings.Contains(record.parts.payload, "bob@example.test") {
		t.Fatal("source persisted without authenticated encryption")
	}
	header, err := f.sealer.Open(f.context, f.scope.TenantID, record.parts.header, f.scope.aad('h'))
	if err != nil || bytes.Contains(header, []byte("bob@example.test")) || bytes.Contains(header, []byte("history")) {
		t.Fatal("minimal header contains source material", err)
	}
	clear(header)
	got, err := f.codec.Open(f.context, f.scope, record, f.authorize)
	if err != nil || !bytes.Equal(got, original) {
		t.Fatal("exact JSON source changed through envelope storage", err)
	}
	clear(got)
	if _, err := json.Marshal(record); !errors.Is(err, errMessagePrivate) {
		t.Fatal("private storage crossed JSON boundary", err)
	}
	if err := json.Unmarshal([]byte(`{}`), &record); !errors.Is(err, errMessagePrivate) {
		t.Fatal("public JSON constructed private storage", err)
	}
	for _, value := range []any{record, &record, struct{ private SealedMessage }{record}, struct{ Public SealedMessage }{record}} {
		if text := fmt.Sprintf("%+v %#v", value, value); strings.Contains(text, record.parts.header) || strings.Contains(text, record.parts.payload) || strings.Contains(text, "bob@example.test") {
			t.Fatal("formatting disclosed private message storage")
		}
	}
}

func TestMessageCodecCurrentAuthorizationPrecedesSourceDecryption(t *testing.T) {
	f := newMessageCodecFixture(t)
	record := f.seal(t, []byte(`{"question":"private original"}`))
	baseOpen := f.codec.open
	payloadOpens, authorizationCalls := 0, 0
	f.codec.open = func(ctx context.Context, tenant, value string, aad []byte) ([]byte, error) {
		if value == record.parts.payload {
			payloadOpens++
		}
		return baseOpen(ctx, tenant, value, aad)
	}
	denied := func(ctx context.Context, scope MessageScope, origin auth.WorkerCredentialRef, requirements []string) error {
		authorizationCalls++
		if err := f.authorize(ctx, scope, origin, requirements); err != nil {
			t.Fatal("callback received changed authenticated provenance", err)
		}
		return errors.New("private backend detail must not cross storage boundary")
	}
	if got, err := f.codec.Open(f.context, f.scope, record, denied); got != nil || !errors.Is(err, ErrMessageDenied) || payloadOpens != 0 || authorizationCalls != 1 {
		t.Fatal("denied current authority decrypted or published source", err)
	}
	if got, err := f.codec.Open(f.context, f.scope, record, nil); got != nil || !errors.Is(err, ErrMessageIntegrity) || payloadOpens != 0 {
		t.Fatal("missing authorization decrypted source", err)
	}
	ctx, cancel := context.WithCancel(f.context)
	if got, err := f.codec.Open(ctx, f.scope, record, func(context.Context, MessageScope, auth.WorkerCredentialRef, []string) error { cancel(); return nil }); got != nil || !errors.Is(err, context.Canceled) || payloadOpens != 0 {
		t.Fatal("canceled current-authority callback decrypted source", err)
	}
	if got, err := f.codec.Open(f.context, f.scope, record, f.authorize); err != nil || string(got) != `{"question":"private original"}` || payloadOpens != 1 {
		t.Fatal("authorized healthy sibling attempt failed", err)
	}
}

func TestMessageCodecTenantOwnerMessageRevisionEpochAndCiphertextSwapsRefuse(t *testing.T) {
	f := newMessageCodecFixture(t)
	record := f.seal(t, []byte(`{"question":"original"}`))
	other := f.seal(t, []byte(`{"question":"other"}`))
	foreign, err := crypto.UUIDv4()
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*MessageScope){
		func(s *MessageScope) { s.TenantID = foreign },
		func(s *MessageScope) { s.OwnerID = foreign },
		func(s *MessageScope) { s.ConversationID = foreign },
		func(s *MessageScope) { s.MessageID = foreign },
		func(s *MessageScope) { s.Revision++ },
		func(s *MessageScope) { s.Epoch++ },
	} {
		scope := f.scope
		change(&scope)
		ctx := tenancy.WithTenant(f.context, tenancy.ID(scope.TenantID))
		calls := 0
		if got, err := f.codec.Open(ctx, scope, record, func(context.Context, MessageScope, auth.WorkerCredentialRef, []string) error { calls++; return nil }); got != nil || !errors.Is(err, ErrMessageIntegrity) || calls != 0 {
			t.Fatal("foreign immutable binding reached source authority", err)
		}
	}
	for _, parts := range []sealedMessageParts{
		{header: record.parts.header, payload: other.parts.payload},
		{header: other.parts.header, payload: record.parts.payload},
		{header: record.parts.header + "!", payload: record.parts.payload},
		{header: record.parts.header, payload: record.parts.payload + "!"},
		{header: "unsealed", payload: record.parts.payload},
	} {
		calls := 0
		if got, err := f.codec.Open(f.context, f.scope, SealedMessage{&parts}, func(context.Context, MessageScope, auth.WorkerCredentialRef, []string) error { calls++; return nil }); got != nil || !errors.Is(err, ErrMessageIntegrity) || calls != 0 {
			t.Fatal("ciphertext swap/tamper reached authorization or source", err)
		}
	}
	if got, err := f.codec.Open(t.Context(), f.scope, record, f.authorize); got != nil || !errors.Is(err, ErrMessageIntegrity) {
		t.Fatal("missing ambient tenant selected private ciphertext", err)
	}
}

func TestMessageCodecKeylessAndUnavailableKeyNeverFallBack(t *testing.T) {
	f := newMessageCodecFixture(t)
	record := f.seal(t, []byte(`{"question":"sealed"}`))
	tenantcrypto.Reset()
	if got, err := f.codec.Seal(f.context, f.scope, f.origin, []string{"flow.read"}, []byte(`{"question":"keyless"}`)); got.parts != nil || !errors.Is(err, ErrMessageUnavailable) {
		t.Fatal("keyless deployment stored plaintext source", err)
	}
	if got, err := f.codec.Open(f.context, f.scope, record, f.authorize); got != nil || !errors.Is(err, ErrMessageIntegrity) {
		t.Fatal("missing key opened retained source", err)
	}
	key, err := crypto.Random(32)
	if err != nil {
		t.Fatal(err)
	}
	currentKey := base64.StdEncoding.EncodeToString(key)
	clear(key)
	current, err := tenantcrypto.NewEnvelopeSealer("new-owned-test-key", currentKey)
	if err != nil {
		t.Fatal(err)
	}
	tenantcrypto.SetPrimary(current)
	if got, err := f.codec.Open(f.context, f.scope, record, f.authorize); got != nil || !errors.Is(err, ErrMessageIntegrity) {
		t.Fatal("removed original key borrowed current key", err)
	}
	ring, err := tenantcrypto.NewEnvelopeKeyringSealer("new-owned-test-key", currentKey, map[string]string{"owned-history-test": f.key})
	if err != nil {
		t.Fatal(err)
	}
	tenantcrypto.SetPrimary(ring)
	if got, err := f.codec.Open(f.context, f.scope, record, f.authorize); err != nil || string(got) != `{"question":"sealed"}` {
		t.Fatal("explicit old-key opener lost authorized source", err)
	}
}
