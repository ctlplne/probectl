// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"context"
	"encoding/hex"
	"encoding/json"

	"github.com/ctlplne/probectl/internal/reporting"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// CreateDocumentChunkedArtifact stores complete static documents in the existing
// artifact chunks. The current database view must have no flow sources; this
// representation cannot substitute for the flow writer's source requirements.
func (DashboardReports) CreateDocumentChunkedArtifact(ctx context.Context, s tenancy.Scope, in ReportArtifactInput, stage *reporting.BodyStage) (*ReportArtifactMetadata, error) {
	tenant, ok := tenancy.FromContext(ctx)
	if !ok || tenant != s.Tenant || len(in.Content) != 0 || stage == nil {
		return nil, ErrReportArtifactIntegrity
	}
	receipt, err := stage.Receipt(ctx)
	if err != nil {
		return nil, err
	}
	digest, err := hex.DecodeString(receipt.SHA256)
	if err != nil || len(digest) != 32 || receipt.Bytes < 1 || receipt.Bytes > reportArtifactMaxBytes {
		return nil, ErrReportArtifactIntegrity
	}
	reader, err := stage.Open(ctx)
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	provenance, err := json.Marshal(in.Provenance)
	if err != nil {
		return nil, err
	}
	limitations, err := json.Marshal(in.CoverageLimitations)
	if err != nil {
		return nil, err
	}
	var out ReportArtifactMetadata
	err = scanReportArtifactMetadata(s.Q.QueryRow(ctx, `INSERT INTO dashboard_report_artifacts AS a
 (tenant_id,id,dashboard_id,schedule_id,format,media_type,filename,content,generated_by,
 absolute_from,absolute_to,provenance,redaction_state,coverage_limitations,body_storage,body_bytes,body_digest,source_capture)
 SELECT $1,$2,$3,$4,$5,$6,$7,NULL,$8,$9,$10,$11::jsonb,$12,$13::jsonb,'document-chunks',$14,$15,NULL
 FROM dashboard_views v
 WHERE v.tenant_id=$1 AND v.id=$3 AND jsonb_typeof(v.definition)='object'
 AND (NOT(v.definition ? 'flow_sources') OR v.definition->'flow_sources'='[]'::jsonb)
 RETURNING `+reportArtifactMetadataColumns,
		s.Tenant.String(), in.ID, in.DashboardID, in.ScheduleID, in.Format, in.MediaType, in.Filename, in.GeneratedBy,
		in.AbsoluteFrom, in.AbsoluteTo, provenance, in.RedactionState, limitations, receipt.Bytes, digest), &out)
	if err != nil {
		return nil, mapWriteErr("static report artifact", err)
	}
	if err := writeReportArtifactChunks(ctx, s, in.ID, reader, receipt.Bytes); err != nil {
		return nil, err
	}
	return &out, nil
}
