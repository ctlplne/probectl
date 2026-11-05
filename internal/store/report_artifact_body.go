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
	"errors"
	"io"

	"github.com/ctlplne/probectl/internal/reporting"
	"github.com/ctlplne/probectl/internal/tenancy"
)

const ReportArtifactSourceEnvelopeMaxBytes = 1 << 20
const reportArtifactMaxBytes = reporting.MaxBodyBytes

var ErrReportArtifactIntegrity = errors.New("stored report body is incomplete or inconsistent")
var ErrReportArtifactSnapshot = errors.New("report body requires a tenant read snapshot")

type ReportArtifactMetadata struct {
	ReportArtifact
	BodyStorage   string          `json:"-"`
	BodyBytes     int64           `json:"body_bytes"`
	BodySHA256    string          `json:"body_sha256,omitempty"`
	SourceCapture json.RawMessage `json:"-"`
}

const reportArtifactHeaderColumns = `a.id,a.tenant_id::text,a.dashboard_id,a.schedule_id,a.format,
 a.media_type,a.filename,a.generated_by,a.generated_at,a.absolute_from,a.absolute_to,
 a.provenance,a.redaction_state,a.coverage_limitations,a.body_storage,
 COALESCE(a.body_bytes,octet_length(a.content)),COALESCE(encode(a.body_digest,'hex'),'')`

const reportArtifactMetadataColumns = reportArtifactHeaderColumns + `,
 CASE WHEN octet_length(a.source_capture::text)<=1048576 THEN a.source_capture ELSE NULL END`

func scanReportArtifactMetadata(row interface{ Scan(...any) error }, out *ReportArtifactMetadata) error {
	var provenance, limitations, capture []byte
	err := row.Scan(&out.ID, &out.TenantID, &out.DashboardID, &out.ScheduleID, &out.Format,
		&out.MediaType, &out.Filename, &out.GeneratedBy, &out.GeneratedAt, &out.AbsoluteFrom, &out.AbsoluteTo,
		&provenance, &out.RedactionState, &limitations, &out.BodyStorage, &out.BodyBytes, &out.BodySHA256, &capture)
	if err != nil {
		return notFound("dashboard report artifact", err)
	}
	out.Provenance = append(out.Provenance[:0], provenance...)
	out.CoverageLimitations = append(out.CoverageLimitations[:0], limitations...)
	out.SourceCapture = append(out.SourceCapture[:0], capture...)
	return nil
}

// GetArtifactMetadata never loads the binary body. Current source/context and
// credential authorization remains the caller's additional publication/read gate.
func (DashboardReports) GetArtifactMetadata(ctx context.Context, s tenancy.Scope, id, userID string) (*ReportArtifactMetadata, error) {
	var out ReportArtifactMetadata
	err := scanReportArtifactMetadata(s.Q.QueryRow(ctx, `SELECT `+reportArtifactMetadataColumns+`
 FROM dashboard_report_artifacts a JOIN dashboard_views v ON v.tenant_id=a.tenant_id AND v.id=a.dashboard_id
 WHERE a.tenant_id=$1 AND a.id=$2 AND (v.owner_id=$3 OR v.shared)`, s.Tenant.String(), id, userID), &out)
	if err != nil {
		return nil, err
	}
	return &out, nil
}

func reportArtifactSourceCapture(tenant string, capture json.RawMessage) error {
	if len(capture) == 0 || len(capture) > ReportArtifactSourceEnvelopeMaxBytes {
		return ErrReportArtifactIntegrity
	}
	var envelope struct {
		Version  int    `json:"version"`
		TenantID string `json:"tenant_id"`
	}
	if err := json.Unmarshal(capture, &envelope); err != nil || envelope.Version != 1 || envelope.TenantID != tenant {
		return ErrReportArtifactIntegrity
	}
	return nil
}

// CreateChunkedArtifact consumes a sealed tenant-owned stage. Its caller must
// return any error from the existing tenant transaction, keeping metadata,
// every chunk, publication audit and schedule advancement atomic.
func (DashboardReports) CreateChunkedArtifact(ctx context.Context, s tenancy.Scope, in ReportArtifactInput,
	stage *reporting.BodyStage, capture json.RawMessage) (*ReportArtifactMetadata, error) {
	tenant, ok := tenancy.FromContext(ctx)
	if !ok || tenant != s.Tenant || len(in.Content) != 0 {
		return nil, ErrReportArtifactIntegrity
	}
	if err := reportArtifactSourceCapture(s.Tenant.String(), capture); err != nil {
		return nil, err
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
 VALUES($1,$2,$3,$4,$5,$6,$7,NULL,$8,$9,$10,$11::jsonb,$12,$13::jsonb,'chunks',$14,$15,$16::jsonb)
 RETURNING `+reportArtifactMetadataColumns,
		s.Tenant.String(), in.ID, in.DashboardID, in.ScheduleID, in.Format, in.MediaType, in.Filename, in.GeneratedBy,
		in.AbsoluteFrom, in.AbsoluteTo, provenance, in.RedactionState, limitations, receipt.Bytes, digest, []byte(capture)), &out)
	if err != nil {
		return nil, mapWriteErr("dashboard report artifact", err)
	}
	if err := writeReportArtifactChunks(ctx, s, in.ID, reader, receipt.Bytes); err != nil {
		return nil, err
	}
	return &out, nil
}

func writeReportArtifactChunks(ctx context.Context, s tenancy.Scope, id string, reader io.Reader, size int64) error {
	buffer := make([]byte, reporting.BodyChunkBytes)
	defer clear(buffer)
	remaining := size
	for ordinal := 0; remaining > 0; ordinal++ {
		count := int(min(remaining, int64(len(buffer))))
		if _, err := io.ReadFull(reader, buffer[:count]); err != nil {
			return err
		}
		// Exec completes parameter encoding before returning; no asynchronous
		// batch retains this copied buffer while its next chunk is read.
		if _, err := s.Q.Exec(ctx, `INSERT INTO dashboard_report_artifact_chunks(tenant_id,artifact_id,ordinal,content) VALUES($1,$2,$3,$4)`, s.Tenant.String(), id, ordinal, buffer[:count]); err != nil {
			return err
		}
		remaining -= int64(count)
	}
	var extra [1]byte
	n, err := reader.Read(extra[:])
	if n != 0 || err != io.EOF {
		return ErrReportArtifactIntegrity
	}
	return nil
}
