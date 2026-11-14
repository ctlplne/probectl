// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/ctlplne/probectl/internal/change"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// OriginalInScope selects one exact tenant-owned change or original archive
// predecessor reference. The caller still owns current source/user checks;
// timeline position, free-form target names and prior responses grant nothing.
func (ChangeEvents) OriginalInScope(ctx context.Context, sc tenancy.Scope, id string, memory int64) (change.Event, error) {
	none := change.Event{}
	bound, ok := tenancy.FromContext(ctx)
	if !ok || bound != sc.Tenant || sc.Q == nil {
		return none, entity.ErrScopeMismatch
	}
	if memory < 4096 {
		return none, ErrClientReportBudget
	}
	if strings.HasPrefix(id, "device-config:") {
		configID := strings.TrimPrefix(id, "device-config:")
		canonical, err := validRegistryUUID(configID)
		if err != nil || canonical != configID {
			return none, entity.ErrInvalidClaim
		}
		var body []byte
		err = sc.Q.QueryRow(ctx, `SELECT CASE WHEN octet_length(body)<=$5::bigint/8 THEN body END
 FROM(SELECT row_to_json(projected)::text AS body FROM(`+configChangeProjectionSQL+`
 AND current.id=$4::uuid) projected) documents`, bound.String(), time.Unix(0, 0).UTC(), time.Now().UTC(), configID, memory).Scan(&body)
		if err != nil {
			return none, notFound("change", err)
		}
		if len(body) == 0 || int64(len(body)) > memory/8 {
			return none, ErrClientReportBudget
		}
		return decodeProjectedConfigChange(body, bound.String())
	}
	canonical, err := validRegistryUUID(id)
	if err != nil || canonical != id {
		return none, entity.ErrInvalidClaim
	}
	var body []byte
	// Bound transfer before decoding the public projection; no private source
	// body is included, including for an untrusted webhook's attributes.
	if err := sc.Q.QueryRow(ctx, `SELECT CASE WHEN octet_length(body)<=$3::bigint/8 THEN body END
 FROM(SELECT row_to_json(original)::text AS body FROM(SELECT `+changeCols+` FROM change_events WHERE tenant_id=$1 AND id=$2) original) documents`, bound.String(), id, memory).Scan(&body); err != nil {
		return none, notFound("change", err)
	}
	if len(body) == 0 || int64(len(body)) > memory/8 {
		return none, ErrClientReportBudget
	}
	var value change.Event
	if err := json.Unmarshal(body, &value); err != nil {
		return none, err
	}
	if value.TenantID != bound.String() {
		return none, entity.ErrScopeMismatch
	}
	if value.Routing != nil {
		if value.Routing.Validate() != nil || value.Kind != change.KindRoute || value.Source != ownedRoutingChangeSource {
			return none, change.ErrRouteReference
		}
	} else if value.Source == ownedRoutingChangeSource {
		return none, change.ErrRouteReference
	}
	return value, ctx.Err()
}
