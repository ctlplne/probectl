// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"context"
	"io"

	"github.com/ctlplne/probectl/internal/reporting"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// StageArtifactBody requires the caller's single routed read snapshot. No body
// escapes until ordered rows, total length and independent stage hash agree.
// Current reader/source authority must be checked again before serving bytes.
func (repo DashboardReports) StageArtifactBody(ctx context.Context, s tenancy.Scope, id, userID string,
	limits reporting.BodyStageLimits) (*ReportArtifactMetadata, *reporting.BodyStage, error) {
	tenant, ok := tenancy.FromContext(ctx)
	if !ok || tenant != s.Tenant {
		return nil, nil, ErrReportArtifactIntegrity
	}
	var isolation string
	if err := s.Q.QueryRow(ctx, `SELECT current_setting('transaction_isolation')`).Scan(&isolation); err != nil {
		return nil, nil, err
	}
	if isolation != "repeatable read" && isolation != "serializable" {
		return nil, nil, ErrReportArtifactSnapshot
	}
	metadata, err := repo.GetArtifactMetadata(ctx, s, id, userID, limits.MemoryBytes)
	if err != nil {
		return nil, nil, err
	}
	maximum := reportArtifactMaxBytes
	switch metadata.BodyStorage {
	case "inline":
		maximum = 2 << 20
		if len(metadata.SourceCapture) != 0 {
			return nil, nil, ErrReportArtifactIntegrity
		}
	case "document-chunks":
		if len(metadata.SourceCapture) != 0 || len(metadata.BodySHA256) != 64 {
			return nil, nil, ErrReportArtifactIntegrity
		}
	case "chunks":
		if err := reportArtifactSourceCapture(s.Tenant.String(), metadata.SourceCapture); err != nil {
			return nil, nil, err
		}
		if len(metadata.BodySHA256) != 64 {
			return nil, nil, ErrReportArtifactIntegrity
		}
	default:
		return nil, nil, ErrReportArtifactIntegrity
	}
	if metadata.BodyBytes < 1 || metadata.BodyBytes > maximum {
		return nil, nil, ErrReportArtifactIntegrity
	}
	stage, err := reporting.NewBodyStage(ctx, s.Tenant.String(), limits)
	if err != nil {
		return nil, nil, err
	}
	fail := func(err error) (*ReportArtifactMetadata, *reporting.BodyStage, error) {
		_ = stage.Close()
		return nil, nil, err
	}
	if metadata.BodyStorage == "inline" {
		err = readInlineReportArtifact(ctx, s, metadata, stage)
	} else {
		err = readReportArtifactChunks(ctx, s, metadata, stage)
	}
	if err != nil {
		return fail(err)
	}
	receipt, err := stage.Seal()
	if err != nil {
		return fail(err)
	}
	if receipt.Bytes != metadata.BodyBytes || (metadata.BodySHA256 != "" && receipt.SHA256 != metadata.BodySHA256) {
		return fail(ErrReportArtifactIntegrity)
	}
	metadata.BodySHA256 = receipt.SHA256
	return metadata, stage, nil
}

func readInlineReportArtifact(ctx context.Context, s tenancy.Scope, metadata *ReportArtifactMetadata, w io.Writer) error {
	var body []byte
	err := s.Q.QueryRow(ctx, `SELECT CASE WHEN octet_length(content) BETWEEN 1 AND 2097152 THEN content ELSE NULL END
 FROM dashboard_report_artifacts WHERE tenant_id=$1 AND id=$2 AND body_storage='inline' AND source_capture IS NULL`, s.Tenant.String(), metadata.ID).Scan(&body)
	if err != nil {
		return err
	}
	defer clear(body)
	if int64(len(body)) != metadata.BodyBytes {
		return ErrReportArtifactIntegrity
	}
	n, err := w.Write(body)
	if err != nil {
		return err
	}
	if n != len(body) {
		return io.ErrShortWrite
	}
	return nil
}

func readReportArtifactChunks(ctx context.Context, s tenancy.Scope, metadata *ReportArtifactMetadata, w io.Writer) error {
	expected := (metadata.BodyBytes + reporting.BodyChunkBytes - 1) / reporting.BodyChunkBytes
	rows, err := s.Q.Query(ctx, `SELECT ordinal,octet_length(content),
 CASE WHEN octet_length(content) BETWEEN 1 AND 65536 THEN content ELSE NULL END
 FROM dashboard_report_artifact_chunks WHERE tenant_id=$1 AND artifact_id=$2 ORDER BY ordinal LIMIT $3`, s.Tenant.String(), metadata.ID, expected+1)
	if err != nil {
		return err
	}
	defer rows.Close()
	var ordinal int64
	remaining := metadata.BodyBytes
	for rows.Next() {
		if err := ctx.Err(); err != nil {
			return err
		}
		var index, length int64
		var body []byte
		if err := rows.Scan(&index, &length, &body); err != nil {
			return err
		}
		want := min(remaining, int64(reporting.BodyChunkBytes))
		if ordinal >= expected || index != ordinal || length != want || int64(len(body)) != want {
			clear(body)
			return ErrReportArtifactIntegrity
		}
		n, err := w.Write(body)
		clear(body)
		if err != nil {
			return err
		}
		if int64(n) != want {
			return io.ErrShortWrite
		}
		ordinal++
		remaining -= want
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if ordinal != expected || remaining != 0 {
		return ErrReportArtifactIntegrity
	}
	return nil
}
