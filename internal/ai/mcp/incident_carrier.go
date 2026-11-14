// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package mcp

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/evidence"
)

type CarrierPackCommand struct {
	IncidentID string    `json:"incident_id"`
	From       time.Time `json:"from"`
	To         time.Time `json:"to"`
}

type CarrierPackBackend interface {
	CarrierPack(context.Context, *auth.Principal, CarrierPackCommand) (SignedCarrierResult, error)
}

// SignedCarrierResult is an already export-redacted carrier package. Its bytes
// are opaque cryptographic material, like a digest or signature, not another
// source-text redaction input. Construction requires an offline-verified
// carrier profile bound to the exact selected tenant and incident.
type SignedCarrierResult struct {
	IncidentID NativeRoleUUID         `json:"incident_id"`
	MediaType  signedCarrierMediaType `json:"media_type"`
	Encoding   string                 `json:"encoding"`
	Package    signedCarrierBytes     `json:"package"`
}

type signedCarrierMediaType string

func (value signedCarrierMediaType) MarshalJSON() ([]byte, error) {
	if value != "application/vnd.probectl.evidence+json" {
		return nil, errors.New("mcp: invalid carrier media type")
	}
	raw, err := json.Marshal(string(value))
	if err != nil {
		return nil, err
	}
	return []byte(strings.ReplaceAll(string(raw), ".", `\u002e`)), nil
}

type signedCarrierBytes string

func NewSignedCarrierResult(raw []byte, tenant, incidentID string) (SignedCarrierResult, error) {
	manifest, err := evidence.Verify(raw)
	if err != nil || manifest == nil || manifest.Profile != "carrier" || manifest.Incident.ID != incidentID || manifest.TenantScopeDigest != "sha256:"+hex.EncodeToString(crypto.Hash([]byte(tenant))) || tenant == "" || !validTagWriteID(incidentID) {
		return SignedCarrierResult{}, errors.New("mcp: verified scoped carrier evidence is required")
	}
	// This fixed profile cannot carry unrelated incident signals or customer
	// prose. The shared source reader applies mandatory export redaction before
	// signing; a second text rewrite would invalidate the original signature.
	if manifest.Incident.Title != "Carrier ticket evidence" || manifest.Incident.Target != "" || manifest.Incident.Prefix != "" || len(manifest.Evidence) != 1 || manifest.Evidence[0].Kind != "incident.carrier" {
		return SignedCarrierResult{}, errors.New("mcp: unrelated signed export profile")
	}
	return SignedCarrierResult{IncidentID: NativeRoleUUID(incidentID), MediaType: "application/vnd.probectl.evidence+json", Encoding: "base64", Package: signedCarrierBytes(base64.StdEncoding.EncodeToString(raw))}, nil
}

func (value signedCarrierBytes) MarshalJSON() ([]byte, error) {
	if value == "" || len(value) > (int(^uint(0)>>1)-2)/6 {
		return nil, errors.New("mcp: invalid signed carrier encoding")
	}
	if _, err := base64.StdEncoding.Strict().DecodeString(string(value)); err != nil {
		return nil, err
	}
	var out strings.Builder
	out.Grow(len(value)*6 + 2)
	out.WriteByte('"')
	for _, c := range string(value) {
		out.WriteString(`\u00`)
		out.WriteByte("0123456789abcdef"[byte(c)>>4])
		out.WriteByte("0123456789abcdef"[byte(c)&15])
	}
	out.WriteByte('"')
	return []byte(out.String()), nil
}

func WithCarrierPackBackend(backend CarrierPackBackend, schema json.RawMessage) Option {
	return func(s *Server) {
		if backend == nil || !json.Valid(schema) {
			return
		}
		tool := Tool{Name: "incident_carrier_pack", Description: "Create a complete redacted signed carrier ticket pack for an incident and past window. Returns base64 bytes for offline verification. Does not send to a carrier or create a public share. Missing/limited trace vantages remain explicit.", InputSchema: append(json.RawMessage(nil), schema...), Permission: "incident.read", ExtraPermissions: []string{"ai.query", "entities.read", "metrics.read", "events.read", "test.read", "change.read"}, Native: true, RequiresUser: true, Query: true,
			Invoke: func(ctx context.Context, actor *auth.Principal, raw json.RawMessage) (any, error) {
				var input CarrierPackCommand
				if err := decodeBoundedNativeArgs(raw, &input, s.nativeRequestBytes()); err != nil {
					return nil, err
				}
				if !validTagWriteID(input.IncidentID) || input.From.IsZero() || !input.To.After(input.From) || input.To.After(time.Now().UTC()) {
					return nil, argErr("canonical incident ID and explicit past from/to are required")
				}
				return backend.CarrierPack(ctx, actor, input)
			}}
		s.nativeEnabled = true
		s.tools[tool.Name] = tool
		s.order = append(s.order, tool.Name)
	}
}
