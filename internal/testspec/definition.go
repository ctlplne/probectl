// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package testspec

import (
	"encoding/hex"
	"encoding/json"

	"github.com/ctlplne/probectl/internal/crypto"
)

// ExecutableDefinition is the exact agent-executable view of a centrally
// distributed synthetic test. Field order and JSON names preserve existing
// signed bundles and definition digests.
type ExecutableDefinition struct {
	ID              string            `json:"id"`
	Type            string            `json:"type"`
	Target          string            `json:"target"`
	IntervalSeconds int               `json:"interval_seconds"`
	TimeoutSeconds  int               `json:"timeout_seconds"`
	Params          map[string]string `json:"params,omitempty"`
}

// DefinitionHash fingerprints the exact executable definition distributed in a
// signed test bundle. It preserves the agent's existing canonical bytes and
// schedule-diff identity. Name, enablement, tenant, agent, context and source
// authority are deliberately not granted by this digest: a receiver must bind
// it to the current enabled test under its authenticated tenant/storage scope.
func DefinitionHash(test ExecutableDefinition) (string, error) {
	raw, err := json.Marshal(test)
	if err != nil {
		return "", err
	}
	digest := crypto.Hash(raw)
	return hex.EncodeToString(digest), nil
}
