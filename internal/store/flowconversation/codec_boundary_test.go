// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flowconversation

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"strings"
	"testing"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestMessageCodecExactAndExceededResources(t *testing.T) {
	f := newMessageCodecFixture(t)
	body := []byte(`{"question":"a complete source document"}`)
	record := f.seal(t, body)
	header, err := f.sealer.Open(f.context, f.scope.TenantID, record.parts.header, f.scope.aad('h'))
	if err != nil {
		t.Fatal(err)
	}
	defer clear(header)
	exact := CodecBudget{PlainBytes: len(body), HeaderBytes: len(header), StoredBytes: len(record.parts.header) + len(record.parts.payload)}
	c := *f.codec
	c.budget = exact
	if got, err := c.Open(f.context, f.scope, record, f.authorize); err != nil || !bytes.Equal(got, body) {
		t.Fatal("exact positive resource limits refused", err)
	}
	if got, err := c.Seal(f.context, f.scope, f.origin, []string{"ai.query", "flow.read", "metrics.read"}, body); err != nil || got.parts == nil {
		t.Fatal("exact write budgets refused", err)
	}
	for _, change := range []func(*CodecBudget){
		func(b *CodecBudget) { b.PlainBytes-- },
		func(b *CodecBudget) { b.HeaderBytes-- },
		func(b *CodecBudget) { b.StoredBytes-- },
	} {
		limited := c
		change(&limited.budget)
		if got, err := limited.Open(f.context, f.scope, record, f.authorize); got != nil || !errors.Is(err, ErrMessageBudget) {
			t.Fatal("over-budget read published partial source", err)
		}
		if got, err := limited.Seal(f.context, f.scope, f.origin, []string{"ai.query", "flow.read", "metrics.read"}, body); got.parts != nil || !errors.Is(err, ErrMessageBudget) {
			t.Fatal("over-budget write persisted partial source", err)
		}
	}
	for _, budget := range []CodecBudget{{}, {PlainBytes: -1, HeaderBytes: 1, StoredBytes: 1}, {PlainBytes: 1, HeaderBytes: 0, StoredBytes: 1}, {PlainBytes: 1, HeaderBytes: 1, StoredBytes: 0}} {
		if codec, err := NewCodec(budget); codec != nil || !errors.Is(err, ErrMessageBudget) {
			t.Fatal("nonpositive operator resource accepted", err)
		}
	}
	for _, invalid := range []string{"", `{"q":`, `{} {}`, `{"q":"\ud800"}`, string([]byte{255})} {
		if got, err := f.codec.Seal(f.context, f.scope, f.origin, []string{"flow.read"}, []byte(invalid)); got.parts != nil || !errors.Is(err, ErrMessageIntegrity) {
			t.Fatal("invalid source JSON admitted", err)
		}
	}
	for _, requirements := range [][]string{nil, {""}, {"FLOW.READ"}, {"flow.read\x00admin"}} {
		if got, err := f.codec.Seal(f.context, f.scope, f.origin, requirements, body); got.parts != nil || !errors.Is(err, ErrMessageBudget) {
			t.Fatal("invalid private requirement syntax admitted", err)
		}
	}
}

func TestMessageCodecAuthenticatedHeaderStrictShapeAndUnknownRequirements(t *testing.T) {
	f := newMessageCodecFixture(t)
	record := f.seal(t, []byte(`{"q":"private"}`))
	header, err := f.sealer.Open(f.context, f.scope.TenantID, record.parts.header, f.scope.aad('h'))
	if err != nil {
		t.Fatal(err)
	}
	defer clear(header)
	credential, err := f.origin.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	countOffset := 4 + 4 + len(credential)
	clear(credential)
	for _, mutate := range []func([]byte) []byte{
		func(b []byte) []byte { b[3] = '2'; return b },
		func(b []byte) []byte { return append(b, 'x') },
		func(b []byte) []byte { return b[:len(b)-1] },
		func(b []byte) []byte { binary.BigEndian.PutUint32(b[4:8], ^uint32(0)); return b },
		func(b []byte) []byte { binary.BigEndian.PutUint32(b[countOffset:countOffset+4], ^uint32(0)); return b },
		func(b []byte) []byte { binary.BigEndian.PutUint32(b[countOffset:countOffset+4], 0); return b },
		func(b []byte) []byte { b[countOffset+8] = 255; return b },
	} {
		bad := mutate(bytes.Clone(header))
		sealed, err := f.sealer.Seal(f.context, f.scope.TenantID, bad, f.scope.aad('h'))
		clear(bad)
		if err != nil {
			t.Fatal(err)
		}
		calls := 0
		if got, err := f.codec.Open(f.context, f.scope, SealedMessage{&sealedMessageParts{header: sealed, payload: record.parts.payload}}, func(context.Context, MessageScope, auth.WorkerCredentialRef, []string) error { calls++; return nil }); got != nil || !errors.Is(err, ErrMessageIntegrity) || calls != 0 {
			t.Fatal("malformed authenticated header reached authorization", err)
		}
	}
	unknown, err := encodeMessageHeader(f.origin, []string{"unregistered.requirement"}, f.codec.budget.HeaderBytes)
	if err != nil {
		t.Fatal(err)
	}
	copy(unknown[len(unknown)-32:], crypto.Hash([]byte(record.parts.payload)))
	sealed, err := f.sealer.Seal(f.context, f.scope.TenantID, unknown, f.scope.aad('h'))
	clear(unknown)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := f.codec.Open(f.context, f.scope, SealedMessage{&sealedMessageParts{header: sealed, payload: record.parts.payload}}, f.authorize); got != nil || !errors.Is(err, ErrMessageDenied) {
		t.Fatal("authenticated metadata became a permission grant", err)
	}
}

func TestMessageCodecCancellationAndScopeDenyBeforeCrypto(t *testing.T) {
	f := newMessageCodecFixture(t)
	record := f.seal(t, []byte(`{"q":"private"}`))
	baseOpen, baseSeal := f.codec.open, f.codec.seal
	opens, seals := 0, 0
	f.codec.open = func(ctx context.Context, tenant, stored string, aad []byte) ([]byte, error) {
		opens++
		return baseOpen(ctx, tenant, stored, aad)
	}
	f.codec.seal = func(ctx context.Context, tenant string, plain, aad []byte) (string, error) {
		seals++
		return baseSeal(ctx, tenant, plain, aad)
	}
	ctx, cancel := context.WithCancel(f.context)
	cancel()
	foreign := tenancy.WithTenant(t.Context(), "another-tenant")
	for _, testContext := range []context.Context{ctx, t.Context(), foreign} {
		if got, err := f.codec.Open(testContext, f.scope, record, f.authorize); got != nil || err == nil {
			t.Fatal("invalid/canceled tenant scope read source")
		}
		if got, err := f.codec.Seal(testContext, f.scope, f.origin, []string{"flow.read"}, []byte(`{}`)); got.parts != nil || err == nil {
			t.Fatal("invalid/canceled tenant scope wrote source")
		}
	}
	if opens != 0 || seals != 0 {
		t.Fatal("invalid tenant/cancellation reached crypto")
	}
	ctx, cancel = context.WithCancel(f.context)
	f.codec.seal = func(ctx context.Context, tenant string, plain, aad []byte) (string, error) {
		seals++
		value, err := baseSeal(ctx, tenant, plain, aad)
		cancel()
		return value, err
	}
	if got, err := f.codec.Seal(ctx, f.scope, f.origin, []string{"flow.read"}, []byte(`{}`)); got.parts != nil || !errors.Is(err, context.Canceled) || seals != 1 {
		t.Fatal("canceled first seal continued to header/publication", err)
	}
	ctx, cancel = context.WithCancel(f.context)
	var opened []byte
	f.codec.open = func(ctx context.Context, tenant, stored string, aad []byte) ([]byte, error) {
		value, err := baseOpen(ctx, tenant, stored, aad)
		if stored == record.parts.payload {
			opened = value
			cancel()
		}
		return value, err
	}
	if got, err := f.codec.Open(ctx, f.scope, record, f.authorize); got != nil || !errors.Is(err, context.Canceled) || len(opened) == 0 || len(bytes.Trim(opened, "\x00")) != 0 {
		t.Fatal("canceled payload open left source output", err)
	}
	partialHeader := []byte("private origin metadata returned alongside an error")
	f.codec.open = func(context.Context, string, string, []byte) ([]byte, error) {
		return partialHeader, errors.New("private diagnostic should be sanitized")
	}
	if got, err := f.codec.Open(f.context, f.scope, record, f.authorize); got != nil || !errors.Is(err, ErrMessageIntegrity) || strings.Contains(err.Error(), "diagnostic") {
		t.Fatal("private crypto diagnostic leaked", err)
	}
	if len(bytes.Trim(partialHeader, "\x00")) != 0 {
		t.Fatal("failed header open retained private origin metadata")
	}
}
