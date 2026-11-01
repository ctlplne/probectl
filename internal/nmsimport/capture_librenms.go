// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package nmsimport

import (
	"context"
	"io"
	"math"

	"github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/tenancy"
)

// CaptureLibreNMSDevices consumes the documented unpaged device-list response
// into bounded tenant transactions, then seals only a complete, valid response.
// The plan must have been started by an authorized caller for this LibreNMS
// instance and routing context; this method never fetches a URL or selects a
// tenant from source JSON. An interrupted stream leaves an inert capture plan.
func (s CaptureStore) CaptureLibreNMSDevices(ctx context.Context,
	contextID, planID string, raw io.Reader) (string, error) {
	if s.pool == nil || s.audit == nil {
		return "", ErrCaptureAuditUnavailable
	}
	contextUUID, err := uuid.Parse(contextID)
	if err != nil || contextUUID == uuid.Nil {
		return "", ErrPlanUnavailable
	}
	planUUID, err := uuid.Parse(planID)
	if err != nil || planUUID == uuid.Nil || raw == nil {
		return "", ErrInvalidPage
	}
	contextID, planID = contextUUID.String(), planUUID.String()
	var pageNumber, firstRow int64
	err = streamLibreNMSDevices(raw, func(snapshot Snapshot) error {
		if pageNumber == math.MaxInt64 || firstRow > math.MaxInt64-int64(len(snapshot.Rows)) {
			return ErrInvalidPage
		}
		var tenantID string
		var meta captureMeta
		if err := tenancy.InTenant(ctx, s.pool, func(ctx context.Context, sc tenancy.Scope) error {
			tenantID = sc.Tenant.String()
			var readErr error
			meta, readErr = loadCaptureMeta(ctx, sc, contextID, planID, false)
			return readErr
		}); err != nil {
			return err
		}
		tenantUUID, err := uuid.Parse(tenantID)
		if err != nil || tenantUUID == uuid.Nil || meta.source != LibreNMS || meta.state != "capturing" {
			return ErrPlanUnavailable
		}
		if _, err := s.appendSnapshot(ctx, contextID, planID, pageNumber,
			"devices", firstRow, tenantUUID.String(), meta, snapshot); err != nil {
			return err
		}
		pageNumber++
		firstRow += int64(len(snapshot.Rows))
		return nil
	})
	if err != nil {
		return "", err
	}
	return s.Seal(ctx, contextID, planID, pageNumber, firstRow)
}
