// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"encoding/json"

	"github.com/ctlplne/probectl/internal/tags"
)

// Reserve space below the shared client/MCP response ceilings. A large value
// shortens a page, never the tenant's stored assignment/rule capacity.
const maxTagPageBytes = 768 << 10

type tagPageBudget struct{ used int }

func (b *tagPageBudget) admit(item any) (bool, error) {
	encoded, err := json.Marshal(item)
	if err != nil {
		return false, err
	}
	if len(encoded)+1 > maxTagPageBytes {
		return false, tags.ErrInvalid
	}
	if len(encoded)+1 > maxTagPageBytes-b.used {
		return false, nil
	}
	b.used += len(encoded) + 1
	return true, nil
}
