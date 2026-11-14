// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package ai

import (
	"encoding/json"
	"errors"
	"maps"
)

// Only this deliberately registered structured source is sent to a model.
// Its producer supplies closed, validated JSON with typed numeric/receipt
// metadata; arbitrary source text still traverses full remote redaction.
func prepareStructuredPrompt(in SynthesisInput, remote bool, policy RedactionPolicy, tenant string) (SynthesisInput, error) {
	out := in
	out.Evidence = append([]Evidence(nil), in.Evidence...)
	for i, evidence := range in.Evidence {
		value, exists := evidence.Fields["path_health"]
		if !exists {
			continue
		}
		body, ok := value.(json.RawMessage)
		if !ok || !json.Valid(body) {
			return SynthesisInput{}, errors.New("ai: invalid complete structured path evidence")
		}
		if remote {
			body = json.RawMessage(redactTextForTenant(string(body), policy, tenant))
		}
		if !json.Valid(body) {
			return SynthesisInput{}, errors.New("ai: structured evidence redaction did not preserve a complete document")
		}
		out.Evidence[i].Fields = maps.Clone(evidence.Fields)
		out.Evidence[i].Fields["path_health"] = body
	}
	return out, nil
}
