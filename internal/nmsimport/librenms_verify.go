// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package nmsimport

import (
	"context"
	"errors"
	"io"
	"math"

	"github.com/jackc/pgx/v5"

	"github.com/ctlplne/probectl/internal/tenancy"
)

// A configured source has no atomic snapshot token. Re-read each fixed
// endpoint before sealing and compare its redacted, bounded pages with the
// committed capture receipts. Drift leaves the plan in capturing state.
func (s CaptureStore) verifyConfiguredLibreNMSInventory(ctx context.Context,
	contextID, planID string, policy LibreNMSFetchPolicy, groupIDs []string) error {
	var meta captureMeta
	var tenantID string
	if err := tenancy.InTenant(ctx, s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		tenantID = sc.Tenant.String()
		var err error
		meta, err = loadCaptureMeta(ctx, sc, contextID, planID, false)
		return err
	}); err != nil {
		return err
	}
	if meta.source != LibreNMS || meta.state != "capturing" {
		return ErrPlanUnavailable
	}
	var pageNumber, firstRow int64
	verifyPage := func(resource string, snapshot Snapshot) error {
		if pageNumber == math.MaxInt64 || firstRow > math.MaxInt64-int64(len(snapshot.Rows)) {
			return ErrInvalidPage
		}
		rows, err := normalizePlanPage(tenantID, contextID, meta.instance,
			meta.generation, meta.source, snapshot, firstRow)
		if err != nil {
			return ErrInvalidPage
		}
		hash, err := normalizedPageHash(tenantID, contextID, meta.instance,
			meta.generation, meta.source, meta.policy, resource, pageNumber, firstRow, rows)
		if err != nil {
			return ErrInvalidPage
		}
		err = tenancy.InTenant(ctx, s.pool, func(ctx context.Context, sc tenancy.Scope) error {
			var storedResource, storedHash string
			var storedFirst, storedRows int64
			err := sc.Q.QueryRow(ctx, `SELECT resource_kind,first_row,row_count,page_hash
				FROM nms_import_pages WHERE tenant_id=$1 AND context_id=$2 AND plan_id=$3
				AND page_number=$4`, sc.Tenant.String(), contextID, planID, pageNumber).
				Scan(&storedResource, &storedFirst, &storedRows, &storedHash)
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrInvalidPage
			}
			if err != nil {
				return err
			}
			if storedResource != resource || storedFirst != firstRow ||
				storedRows != int64(len(rows)) || storedHash != hash {
				return ErrInvalidPage
			}
			return nil
		})
		if err != nil {
			return err
		}
		pageNumber++
		firstRow += int64(len(rows))
		return nil
	}
	verify := func(resource, groupID string, stream func(io.Reader, func(Snapshot) error) error) error {
		var body io.ReadCloser
		var err error
		if groupID == "" {
			body, err = s.OpenConfiguredLibreNMS(ctx, contextID, planID, resource, policy)
		} else {
			body, err = s.OpenConfiguredLibreNMSMembership(ctx, contextID, planID, groupID, policy)
		}
		if err != nil {
			return err
		}
		defer body.Close()
		return stream(body, func(snapshot Snapshot) error { return verifyPage(resource, snapshot) })
	}
	for _, resource := range []struct {
		name   string
		stream func(io.Reader, func(Snapshot) error) error
	}{
		{"devices", streamLibreNMSDevices},
		{"locations", streamLibreNMSLocations},
		{"groups", streamCapturedLibreNMSGroups},
	} {
		if err := verify(resource.name, "", resource.stream); err != nil {
			return err
		}
	}
	for _, groupID := range groupIDs {
		id := groupID
		if err := verify("memberships", id, func(raw io.Reader, emit func(Snapshot) error) error {
			return streamLibreNMSGroupMembers(raw, id, emit)
		}); err != nil {
			return err
		}
	}
	if err := verify("rules", "", streamLibreNMSRules); err != nil {
		return err
	}
	return tenancy.InTenant(ctx, s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		var actualPages, actualRows int64
		if err := sc.Q.QueryRow(ctx, `SELECT count(*),coalesce(sum(row_count),0)
			FROM nms_import_pages WHERE tenant_id=$1 AND context_id=$2 AND plan_id=$3`,
			sc.Tenant.String(), contextID, planID).Scan(&actualPages, &actualRows); err != nil {
			return err
		}
		if actualPages != pageNumber || actualRows != firstRow {
			return ErrInvalidPage
		}
		return nil
	})
}
