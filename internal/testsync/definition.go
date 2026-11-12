// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package testsync

import (
	"encoding/hex"
	"encoding/json"

	"github.com/ctlplne/probectl/internal/crypto"
)

// DefinitionHash fingerprints the exact executable definition distributed in a
// signed test bundle. It preserves the agent's existing canonical bytes and
// schedule-diff identity. Name, enablement, tenant, agent, context and source
// authority are deliberately not granted by this digest: a receiver must bind
// it to the current enabled test under its authenticated tenant/storage scope.
func DefinitionHash(test Test) (string, error) {
	raw, err := json.Marshal(test)
	if err != nil {
		return "", err
	}
	digest := crypto.Hash(raw)
	return hex.EncodeToString(digest), nil
}
