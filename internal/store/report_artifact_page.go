// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/ctlplne/probectl/internal/tenancy"
)

// Physical query batches do not limit total inbox reach or public page sizes.
const ReportArtifactHeaderBatchRows = 200

var ErrReportMetadataBudget = errors.New("report metadata operation budget exceeded")

type ReportArtifactPosition struct {
	GeneratedAt time.Time `json:"generated_at"`
	ID          string    `json:"id"`
}

// ListArtifactHeaderBatch reads metadata only. Keyset, tenant and current view
// ownership are applied in SQL; source authorization remains an additional gate.
// Charge every scanned header, including hidden items, before retaining it.
func (DashboardReports) ListArtifactHeaderBatch(ctx context.Context, s tenancy.Scope, userID string, before *ReportArtifactPosition, memoryBytes int64) ([]ReportArtifactMetadata, int64, error) {
	if tenant, ok := tenancy.FromContext(ctx); !ok || tenant != s.Tenant {
		return nil, 0, tenancy.ErrNoTenant
	}
	if memoryBytes <= 0 {
		return nil, 0, ErrReportMetadataBudget
	}
	var at any
	id := ""
	if before != nil {
		at, id = before.GeneratedAt, before.ID
	}
	rows, err := s.Q.Query(ctx, `SELECT `+reportArtifactHeaderColumns+`,NULL::jsonb
 FROM dashboard_report_artifacts a JOIN dashboard_views v ON v.tenant_id=a.tenant_id AND v.id=a.dashboard_id
 WHERE a.tenant_id=$1 AND (v.owner_id=$2 OR v.shared)
 AND ((a.body_storage IN ('inline','document-chunks') AND a.source_capture IS NULL) OR a.body_storage='chunks')
 AND ($3::timestamptz IS NULL OR (a.generated_at,a.id)<($3::timestamptz,$4::text))
 ORDER BY a.generated_at DESC,a.id DESC LIMIT $5`, s.Tenant.String(), userID, at, id, ReportArtifactHeaderBatchRows)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := make([]ReportArtifactMetadata, 0)
	var charged int64
	for rows.Next() {
		if err := ctx.Err(); err != nil {
			return nil, 0, err
		}
		var item ReportArtifactMetadata
		if err := scanReportArtifactMetadata(rows, &item); err != nil {
			return nil, 0, err
		}
		raw, err := json.Marshal(item)
		if err != nil {
			return nil, 0, err
		}
		// Cover decoded fields, row/slice storage and response projection work.
		remaining := memoryBytes - charged
		if remaining <= 1024 || int64(len(raw)) > (remaining-1024)/4 {
			return nil, 0, ErrReportMetadataBudget
		}
		charged += int64(len(raw))*4 + 1024
		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	return out, charged, nil
}
