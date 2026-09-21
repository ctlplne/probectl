// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package ai

import "time"

// Row is one normalized result record.
type Row map[string]any

// Result is the normalized envelope every query returns, with provenance.
type Result struct {
	Tenant    string   // the principal's tenant — the scope of this result
	Domains   []Domain // which domains contributed (provenance)
	Rows      []Row
	Truncated bool // a cost guard capped the rows
	Elapsed   time.Duration
}
