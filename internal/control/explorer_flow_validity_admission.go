// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"bytes"
	"context"
	"encoding/json"
	"io"

	"github.com/ctlplne/probectl/internal/store/flowstore"
)

// Admit complete JSON shape before its typed slices/strings are allocated.
// Ciphertext and tenant byte admission remain enforced by snapshot storage.
func admitFlowSnapshotValidity(ctx context.Context, proof []byte, bytesLimit, memory int64) error {
	if bytesLimit <= 0 || memory <= 0 || int64(len(proof)) > bytesLimit || int64(len(proof)) > memory/4 {
		return flowstore.ErrExplorerBudget
	}
	decoder := json.NewDecoder(bytes.NewReader(proof))
	decoder.UseNumber()
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		token, err := decoder.Token()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return flowstore.ErrSnapshotInputs
		}
		cost := int64(64)
		if delimiter, ok := token.(json.Delim); ok && (delimiter == '{' || delimiter == '[') {
			cost = 512
		}
		if value, ok := token.(string); ok {
			cost += int64(len(value)) * 2
		}
		if cost > memory {
			return flowstore.ErrExplorerBudget
		}
		memory -= cost
	}
}
