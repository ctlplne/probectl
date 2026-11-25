// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package mcp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"regexp"
	"strings"

	"github.com/ctlplne/probectl/internal/ai"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/evidence"
	"github.com/ctlplne/probectl/internal/incident"
)

type IncidentDraftCommand struct {
	IncidentID string                 `json:"incident_id"`
	Kind       evidence.DraftKind     `json:"kind"`
	Carrier    *incident.CarrierInput `json:"carrier,omitempty"`
	Impact     *incident.ImpactInput  `json:"impact,omitempty"`
	Verdict    *incident.VerdictInput `json:"verdict,omitempty"`
}

type SignedIncidentDraft struct {
	Kind            evidence.DraftKind   `json:"kind"`
	PackageID       draftReference       `json:"package_id"`
	Sections        []nativeDraftSection `json:"sections"`
	Model           string               `json:"model"`
	Degraded        bool                 `json:"degraded"`
	EvidencePackage signedCarrierBytes   `json:"evidence_package"`
}

type nativeDraftSection struct {
	Name      string                `json:"name"`
	Sentences []nativeDraftSentence `json:"sentences"`
}

type nativeDraftSentence struct {
	Text      string                `json:"text"`
	State     evidence.State        `json:"state"`
	Citations []nativeDraftCitation `json:"citations"`
}

type nativeDraftCitation struct {
	EvidenceID draftReference `json:"evidence_id,omitempty"`
	Pointer    draftPointer   `json:"pointer"`
}

// NewSignedIncidentDraft preserves approved evidence bytes, canonical digest
// references and JSON Pointers through the ordinary MCP text redaction. Draft
// prose still goes through that redaction before it crosses the transport.
func NewSignedIncidentDraft(draft evidence.IncidentDraft, model string, degraded bool, raw []byte, tenant, id, signer string) (SignedIncidentDraft, error) {
	verified, err := evidence.OpenDraftSource(raw, tenant, id, signer)
	if err != nil || draft.PackageID != verified.PackageID() {
		return SignedIncidentDraft{}, evidence.ErrDraftSource
	}
	result := SignedIncidentDraft{Kind: draft.Kind, PackageID: draftReference(draft.PackageID), Model: model, Degraded: degraded,
		EvidencePackage: signedCarrierBytes(base64.StdEncoding.EncodeToString(raw)), Sections: make([]nativeDraftSection, 0, len(draft.Sections))}
	for _, section := range draft.Sections {
		projected := nativeDraftSection{Name: section.Name, Sentences: make([]nativeDraftSentence, 0, len(section.Sentences))}
		for _, sentence := range section.Sentences {
			if len(sentence.Citations) == 0 {
				return SignedIncidentDraft{}, evidence.ErrDraftClaim
			}
			citations := make([]nativeDraftCitation, len(sentence.Citations))
			for i, citation := range sentence.Citations {
				if _, ok := verified.Resolve(citation); !ok {
					return SignedIncidentDraft{}, evidence.ErrDraftClaim
				}
				citations[i] = nativeDraftCitation{draftReference(citation.EvidenceID), draftPointer(citation.Pointer)}
			}
			projected.Sentences = append(projected.Sentences, nativeDraftSentence{sentence.Text, sentence.State, citations})
		}
		result.Sections = append(result.Sections, projected)
	}
	return result, nil
}

type draftReference string

func (r draftReference) MarshalJSON() ([]byte, error) {
	for _, scheme := range []struct {
		prefix string
		bytes  int
	}{{"pkg_", 16}, {"evidence:sha256:", 32}} {
		value, hasPrefix := strings.CutPrefix(string(r), scheme.prefix)
		if hasPrefix {
			hex, err := encodeNativeHex(value, scheme.bytes)
			if err != nil {
				return nil, err
			}
			return []byte(`"` + scheme.prefix + string(hex[1:])), nil
		}
	}
	return nil, errors.New("invalid signed draft reference")
}

type draftPointer string

var generatedDraftPointer = regexp.MustCompile(`^(?:/[a-z0-9_]+)+$`)

func (p draftPointer) MarshalJSON() ([]byte, error) {
	if !generatedDraftPointer.MatchString(string(p)) {
		return nil, errors.New("invalid signed draft evidence path")
	}
	var out strings.Builder
	out.WriteByte('"')
	for _, c := range p {
		switch {
		case c == '/':
			out.WriteString(`\u002f`)
		case c >= '0' && c <= '9':
			out.WriteString(`\u003`)
			out.WriteRune(c)
		default:
			out.WriteRune(c)
		}
	}
	out.WriteByte('"')
	return []byte(out.String()), nil
}

func WithIncidentDraftBackend(backend func(context.Context, *auth.Principal, IncidentDraftCommand, ai.RedactionPolicy) (SignedIncidentDraft, error), schema json.RawMessage) Option {
	return func(s *Server) {
		if backend == nil || !json.Valid(schema) {
			return
		}
		tool := Tool{
			Name: "incident_draft", Description: "Prepare a carrier ticket, postmortem, or executive summary from signed tenant incident evidence. Returns a cited draft and its signed source for operator review.",
			Permission: permIncidentRead, ExtraPermissions: []string{permAIQuery}, RequiresUser: true, Native: true, Query: true,
			InputSchema: append(json.RawMessage(nil), schema...),
			Invoke: func(ctx context.Context, actor *auth.Principal, args json.RawMessage) (any, error) {
				var selection IncidentDraftCommand
				if err := decodeBoundedNativeArgs(args, &selection, s.nativeRequestBytes()); err != nil {
					return nil, err
				}
				return backend(ctx, actor, selection, s.gate.SignedExportRedaction())
			},
		}
		s.nativeEnabled = true
		s.tools[tool.Name] = tool
		s.order = append(s.order, tool.Name)
	}
}
