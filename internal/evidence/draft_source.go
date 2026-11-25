// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package evidence

import (
	"encoding/json"
	"errors"
	"strconv"
	"strings"
)

var ErrDraftSource = errors.New("evidence: trusted incident draft source is unavailable")

// DraftCitation points into the verified signed package. An empty EvidenceID
// selects the manifest, and a nonempty ID selects its verified attachment.
type DraftCitation struct {
	EvidenceID string `json:"evidence_id,omitempty"`
	Pointer    string `json:"pointer"`
}

// DraftSource is a verified package for the current tenant, incident and signer.
// Only the service's authenticated export path may supply the expected binding.
type DraftSource struct {
	manifest     Manifest
	manifestJSON json.RawMessage
	attachments  map[string]json.RawMessage
}

func (s *DraftSource) PackageID() string { return s.manifest.PackageID }

// OpenDraftSource checks deployment signer trust and the tenant and incident
// binding in addition to the ordinary offline package integrity checks.
func OpenDraftSource(raw []byte, tenant, incidentID, trustedSignerFingerprint string) (*DraftSource, error) {
	if tenant == "" || incidentID == "" || trustedSignerFingerprint == "" {
		return nil, ErrDraftSource
	}
	var wire Package
	if err := json.Unmarshal(raw, &wire); err != nil || wire.Signing.Fingerprint != trustedSignerFingerprint {
		return nil, ErrDraftSource
	}
	manifest, err := wire.verify()
	if err != nil || manifest.TenantScopeDigest != digest([]byte(tenant)) || manifest.Incident.ID != incidentID {
		return nil, ErrDraftSource
	}
	byDigest := make(map[string]json.RawMessage, len(wire.Attachments))
	for _, attachment := range wire.Attachments {
		byDigest[attachment.Digest] = attachment.Content
	}
	byID := make(map[string]json.RawMessage, len(manifest.Evidence))
	for _, record := range manifest.Evidence {
		byID[record.ID] = byDigest[record.AttachmentDigest]
	}
	return &DraftSource{manifest: *manifest, manifestJSON: wire.Manifest, attachments: byID}, nil
}

// Resolve returns a new JSON value for a draft citation. Missing, malformed,
// and foreign evidence references have the same result.
func (s *DraftSource) Resolve(citation DraftCitation) (json.RawMessage, bool) {
	if s == nil || !strings.HasPrefix(citation.Pointer, "/") {
		return nil, false
	}
	value := s.manifestJSON
	if citation.EvidenceID != "" {
		value = s.attachments[citation.EvidenceID]
	}
	for key := range strings.SplitSeq(citation.Pointer[1:], "/") {
		key, ok := draftPointerToken(key)
		if !ok {
			return nil, false
		}
		if len(value) == 0 {
			return nil, false
		}
		switch value[0] {
		case '{':
			var object map[string]json.RawMessage
			if err := json.Unmarshal(value, &object); err != nil {
				return nil, false
			}
			value = object[key]
		case '[':
			var array []json.RawMessage
			index, err := strconv.Atoi(key)
			if err != nil || strconv.Itoa(index) != key || index < 0 || json.Unmarshal(value, &array) != nil || index >= len(array) {
				return nil, false
			}
			value = array[index]
		default:
			return nil, false
		}
	}
	if len(value) == 0 {
		return nil, false
	}
	return value, true
}

func draftPointerToken(token string) (string, bool) {
	for rest := token; ; {
		i := strings.IndexByte(rest, '~')
		if i < 0 {
			return strings.ReplaceAll(strings.ReplaceAll(token, "~1", "/"), "~0", "~"), true
		}
		if i+1 == len(rest) || rest[i+1] != '0' && rest[i+1] != '1' {
			return "", false
		}
		rest = rest[i+2:]
	}
}
