// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package entity

import "time"

// ContextRecord is one tenant-owned routing-context configuration. These
// identifiers are operator configuration, never a selector from telemetry.
type ContextRecord struct {
	TenantID  string    `json:"tenant_id"`
	ContextID string    `json:"context_id"`
	SiteID    string    `json:"site_id"`
	VRFID     string    `json:"vrf_id"`
	SiteLabel string    `json:"site_label"`
	VRFLabel  string    `json:"vrf_label"`
	CreatedAt time.Time `json:"created_at"`
}

type ContextPage struct {
	Items      []ContextRecord `json:"items"`
	NextCursor string          `json:"next_cursor,omitempty"`
}
