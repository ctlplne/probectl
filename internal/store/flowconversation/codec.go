// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

// Package flowconversation owns private flow-question storage primitives.
// These primitives grant no access and expose no public history service.
package flowconversation

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"

	"github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/tenantcrypto"
	"github.com/ctlplne/probectl/internal/wire"
)

var (
	ErrMessageIntegrity   = errors.New("flow conversation: private message integrity refused")
	ErrMessageBudget      = errors.New("flow conversation: private message resource budget exceeded")
	ErrMessageUnavailable = errors.New("flow conversation: private message encryption unavailable")
	ErrMessageDenied      = errors.New("flow conversation: current message authority refused")
	errMessagePrivate     = errors.New("flow conversation: sealed messages require private storage")
)

// MessageScope binds an immutable revision and its lifecycle generation. The
// ambient tenant must match before any crypto, callback or storage access.
type MessageScope struct {
	TenantID, OwnerID, ConversationID, MessageID string
	Revision, Epoch                              uint64
}

// CodecBudget controls allocation/work, not conversation history or turns.
// All positive limits can be raised by an operator; no silent truncation.
type CodecBudget struct{ PlainBytes, HeaderBytes, StoredBytes int }

func DefaultCodecBudget() CodecBudget {
	return CodecBudget{PlainBytes: 16 << 20, HeaderBytes: 1 << 20, StoredBytes: 64 << 20}
}

func (b CodecBudget) valid() bool { return b.PlainBytes > 0 && b.HeaderBytes > 0 && b.StoredBytes > 0 }

// AuthorizeMessage must revalidate the current operation's exact credential and
// every authenticated requirement. Workers use the immutable stored origin;
// explicit owner-history reads independently use their authenticated current
// credential. Requirements and old origins are never grants. The
// service must independently derive their complete union from original input,
// parent/source context and plan at admission, then fence execution/publication.
// No source-bearing payload is opened if this callback is missing or fails.
type AuthorizeMessage func(context.Context, MessageScope, auth.WorkerCredentialRef, []string) error

// SealedMessage is immutable private storage, never a public capability. An
// opaque pointer also prevents nested fmt traversal into its ciphertext fields.
type SealedMessage struct{ parts *sealedMessageParts }
type sealedMessageParts struct{ header, payload string }

func (SealedMessage) MarshalJSON() ([]byte, error) { return nil, errMessagePrivate }
func (*SealedMessage) UnmarshalJSON([]byte) error  { return errMessagePrivate }
func (SealedMessage) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, "flowconversation.SealedMessage[private]")
}

// Codec uses only the existing tenant encryption dispatcher. It refuses the
// dispatcher's keyless-development plaintext path for this sensitive material.
type Codec struct {
	budget    CodecBudget
	seal      func(context.Context, string, []byte, []byte) (string, error)
	open      func(context.Context, string, string, []byte) ([]byte, error)
	hasScheme func(string) bool
}

func NewCodec(budget CodecBudget) (*Codec, error) {
	if !budget.valid() {
		return nil, ErrMessageBudget
	}
	return &Codec{budget: budget, seal: tenantcrypto.Seal, open: tenantcrypto.Open, hasScheme: tenantcrypto.HasScheme}, nil
}

func (s MessageScope) validate(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	ambient, ok := tenancy.FromContext(ctx)
	if !ok || ambient.String() != s.TenantID || s.Revision == 0 || s.Epoch == 0 {
		return ErrMessageIntegrity
	}
	for _, id := range []string{s.TenantID, s.OwnerID, s.ConversationID, s.MessageID} {
		parsed, err := uuid.Parse(id)
		if err != nil || parsed.String() != id {
			return ErrMessageIntegrity
		}
	}
	return nil
}

func (s MessageScope) aad(kind byte) []byte {
	out := append([]byte("probectl.flow.conversation.v1\x00"), kind)
	for _, id := range []string{s.TenantID, s.OwnerID, s.ConversationID, s.MessageID} {
		out = append(out, id...)
	}
	out = binary.BigEndian.AppendUint64(out, s.Revision)
	return binary.BigEndian.AppendUint64(out, s.Epoch)
}

func (c *Codec) available() error {
	if c == nil || !c.budget.valid() || c.seal == nil || c.open == nil || c.hasScheme == nil {
		return ErrMessageUnavailable
	}
	return nil
}

func messageError(ctx context.Context, otherwise error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return otherwise
}

func exactMessageJSON(ctx context.Context, body []byte) bool {
	return wire.ExactJSONUnicode(ctx, string(body)) && json.Valid(body) && ctx.Err() == nil
}

// Seal admits no permission itself. The caller must authorize admission and
// atomically persist its audit, immutable input and queued work under owner RLS.
func (c *Codec) Seal(ctx context.Context, scope MessageScope, origin auth.WorkerCredentialRef, requirements []string, body []byte) (SealedMessage, error) {
	if err := scope.validate(ctx); err != nil {
		return SealedMessage{}, err
	}
	if err := c.available(); err != nil {
		return SealedMessage{}, err
	}
	if _, _, err := origin.ScopedID(scope.TenantID, scope.OwnerID); err != nil {
		return SealedMessage{}, ErrMessageIntegrity
	}
	if len(body) > c.budget.PlainBytes {
		return SealedMessage{}, ErrMessageBudget
	}
	plain := bytes.Clone(body)
	defer clear(plain)
	if !exactMessageJSON(ctx, plain) {
		return SealedMessage{}, messageError(ctx, ErrMessageIntegrity)
	}
	header, err := encodeMessageHeader(origin, requirements, c.budget.HeaderBytes)
	if err != nil {
		return SealedMessage{}, err
	}
	defer clear(header)
	payload, err := c.seal(ctx, scope.TenantID, plain, scope.aad('p'))
	if err != nil || !c.hasScheme(payload) {
		return SealedMessage{}, messageError(ctx, ErrMessageUnavailable)
	}
	if err := ctx.Err(); err != nil {
		return SealedMessage{}, err
	}
	copy(header[len(header)-32:], crypto.Hash([]byte(payload)))
	sealedHeader, err := c.seal(ctx, scope.TenantID, header, scope.aad('h'))
	if err != nil || !c.hasScheme(sealedHeader) {
		return SealedMessage{}, messageError(ctx, ErrMessageUnavailable)
	}
	if len(payload) > c.budget.StoredBytes || len(sealedHeader) > c.budget.StoredBytes-len(payload) {
		return SealedMessage{}, ErrMessageBudget
	}
	if err := ctx.Err(); err != nil {
		return SealedMessage{}, err
	}
	return SealedMessage{&sealedMessageParts{header: sealedHeader, payload: payload}}, nil
}

// Open decrypts only the authenticated private origin/requirements header before
// current authorization. The returned source bytes belong to the caller, which
// must clear them after use and independently revalidate sources/publication.
func (c *Codec) Open(ctx context.Context, scope MessageScope, record SealedMessage, authorize AuthorizeMessage) ([]byte, error) {
	parts, err := c.authorizedParts(ctx, scope, record, authorize)
	if err != nil {
		return nil, err
	}
	body, err := c.open(ctx, scope.TenantID, parts.payload, scope.aad('p'))
	if err != nil {
		clear(body)
		return nil, messageError(ctx, ErrMessageIntegrity)
	}
	if len(body) > c.budget.PlainBytes {
		clear(body)
		return nil, ErrMessageBudget
	}
	if !exactMessageJSON(ctx, body) {
		clear(body)
		return nil, messageError(ctx, ErrMessageIntegrity)
	}
	return body, nil
}

// CheckHeader authenticates the scope/origin/requirements and ciphertext pair,
// then requires current authorization without opening source-bearing payload.
// It is not a capability; Open must independently authorize again before use.
func (c *Codec) CheckHeader(ctx context.Context, scope MessageScope, record SealedMessage, authorize AuthorizeMessage) error {
	_, err := c.authorizedParts(ctx, scope, record, authorize)
	return err
}

func (c *Codec) authorizedParts(ctx context.Context, scope MessageScope, record SealedMessage, authorize AuthorizeMessage) (sealedMessageParts, error) {
	if err := scope.validate(ctx); err != nil {
		return sealedMessageParts{}, err
	}
	if err := c.available(); err != nil {
		return sealedMessageParts{}, err
	}
	if record.parts == nil || authorize == nil {
		return sealedMessageParts{}, ErrMessageIntegrity
	}
	// Keep the authenticated pair stable across the external authorization port,
	// including future private repositories that reuse their row backing value.
	parts := *record.parts
	if len(parts.payload) > c.budget.StoredBytes || len(parts.header) > c.budget.StoredBytes-len(parts.payload) {
		return sealedMessageParts{}, ErrMessageBudget
	}
	if !c.hasScheme(parts.header) || !c.hasScheme(parts.payload) {
		return sealedMessageParts{}, ErrMessageIntegrity
	}
	header, err := c.open(ctx, scope.TenantID, parts.header, scope.aad('h'))
	if err != nil {
		clear(header)
		return sealedMessageParts{}, messageError(ctx, ErrMessageIntegrity)
	}
	defer clear(header)
	if len(header) > c.budget.HeaderBytes {
		return sealedMessageParts{}, ErrMessageBudget
	}
	origin, requirements, digest, err := decodeMessageHeader(header)
	if err != nil {
		return sealedMessageParts{}, err
	}
	if _, _, err := origin.ScopedID(scope.TenantID, scope.OwnerID); err != nil || !crypto.ConstantTimeEqual(digest, crypto.Hash([]byte(parts.payload))) {
		return sealedMessageParts{}, ErrMessageIntegrity
	}
	if err := ctx.Err(); err != nil {
		return sealedMessageParts{}, err
	}
	if err := authorize(ctx, scope, origin, requirements); err != nil {
		return sealedMessageParts{}, messageError(ctx, ErrMessageDenied)
	}
	if err := ctx.Err(); err != nil {
		return sealedMessageParts{}, err
	}
	return parts, nil
}

func canonicalMessageRequirements(input []string, budget int) ([]string, error) {
	if len(input) == 0 || len(input) > budget/5 {
		return nil, ErrMessageBudget
	}
	used := 0
	for _, requirement := range input {
		if len(requirement) > budget-used || !messageRequirement(requirement) {
			return nil, ErrMessageBudget
		}
		used += len(requirement)
	}
	result := slices.Clone(input)
	slices.Sort(result)
	return slices.Compact(result), nil
}

func messageRequirement(value string) bool {
	if value == "" {
		return false
	}
	for _, c := range []byte(value) {
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '_' && c != '.' && c != '-' {
			return false
		}
	}
	return true
}
