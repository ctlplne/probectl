// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"encoding/json"
	"github.com/ctlplne/probectl/internal/ai/mcp"
	"github.com/ctlplne/probectl/internal/change"
)

// Only verified original references enter this projection, after current source
// authorization. Closed numeric protocol metadata and stored UUIDs remain exact;
// sender/free-form text in the enclosing row still receives full redaction.
func nativeRoutingChangeReference(reference change.RouteReference) (json.RawMessage, error) {
	if err := reference.Validate(); err != nil {
		return nil, err
	}
	body, err := json.Marshal(reference)
	if err != nil {
		return nil, err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(body, &fields); err != nil {
		return nil, err
	}
	for key, value := range map[string]string{"context_id": reference.ContextID, "router_id": reference.RouterID, "base_context_id": reference.BaseContextID, "base_router_id": reference.BaseRouterID, "view_id": reference.ViewID, "generation": reference.Generation} {
		encoded, err := json.Marshal(mcp.NativeRoleUUID(value))
		if err != nil {
			return nil, err
		}
		fields[key] = encoded
	}
	fields["sequence"], err = json.Marshal(mcp.NativeRoleRevision(reference.Sequence))
	if err != nil {
		return nil, err
	}
	fields["batch_digest"], err = json.Marshal(mcp.NativeRoleDigest(reference.BatchDigest))
	if err != nil {
		return nil, err
	}
	return json.Marshal(fields)
}
