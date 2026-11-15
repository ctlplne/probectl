// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package pipeline

import (
	"context"
	"encoding/json"
	"time"

	flowv1 "github.com/ctlplne/probectl/internal/gen/probectl/flow/v1"
	"github.com/ctlplne/probectl/internal/opendata"
	"github.com/ctlplne/probectl/internal/store/flowstore"
)

// WithServiceRanges attaches local public reference data at the production
// composition seam. Sender protobufs cannot assert these storage-only fields.
// The existing source profile also bounds additional buffered attribution data.
func (c *FlowConsumer) WithServiceRanges(source *opendata.Enricher, memoryBytes int64) *FlowConsumer {
	c.serviceRanges, c.serviceMemoryBytes = source, memoryBytes
	return c
}

type flowServiceEvidence struct {
	Version     int                            `json:"version"`
	Source      opendata.ServiceClassification `json:"source"`
	Destination opendata.ServiceClassification `json:"destination"`
}

func (c *FlowConsumer) projectFlowService(ctx context.Context, row *flowstore.Row, at time.Time) error {
	row.SrcServiceStatus, row.DstServiceStatus = "unknown", "unknown"
	if c.serviceRanges == nil {
		return nil
	}
	src := c.serviceRanges.LocalServiceRanges(ctx, row.SrcAddr, at)
	dst := c.serviceRanges.LocalServiceRanges(ctx, row.DstAddr, at)
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(src) == 0 && len(dst) == 0 {
		return nil
	}
	evidence := flowServiceEvidence{Version: 1, Source: opendata.ClassifyServiceRanges(src, at), Destination: opendata.ClassifyServiceRanges(dst, at)}
	raw, err := json.Marshal(evidence)
	if err != nil {
		return err
	}
	row.SrcService, row.SrcServiceRegion, row.SrcServiceProvider, row.SrcServiceStatus = evidence.Source.Service, evidence.Source.Region, evidence.Source.Provider, evidence.Source.Status
	row.DstService, row.DstServiceRegion, row.DstServiceProvider, row.DstServiceStatus = evidence.Destination.Service, evidence.Destination.Region, evidence.Destination.Provider, evidence.Destination.Status
	row.ServiceClassifiedAt, row.ServiceEvidence = at.UTC().Format(time.RFC3339Nano), string(raw)
	return nil
}

// Classify after complete tenant/signature/original-capture admission. Flush
// complete chunks when additional attribution bytes reach the source profile;
// never shrink a flow batch, truncate provenance or multiply traffic by matches.
// Store writes retain the existing retry/DLQ contract and original dedup keys.
func (c *FlowConsumer) projectAndInsertFlowRows(ctx context.Context, tenant string, records []*flowv1.FlowRecord, captures []flowCaptureProjection) error {
	at := time.Now().UTC()
	limit := c.serviceMemoryBytes
	if limit <= 0 {
		limit = 256 << 20
	}
	rows := make([]flowstore.Row, 0, min(len(records), 1024))
	var additionalBytes int64
	for i, record := range records {
		if err := ctx.Err(); err != nil {
			return err
		}
		record.TenantId = tenant
		c.enrichRecord(ctx, record)
		row := projectedFlowCapture(record, captures, i)
		if err := c.projectFlowService(ctx, &row, at); err != nil {
			return err
		}
		bytes := flowstore.ServiceAttributionBytes(row)
		if additionalBytes > 0 && bytes > limit-additionalBytes {
			if err := c.insertWithRetry(ctx, rows); err != nil {
				return err
			}
			rows = nil
			additionalBytes = 0
		}
		rows = append(rows, row)
		additionalBytes += bytes
		// A complete individual attribution can exceed a deliberately smaller
		// batch profile. Stream it alone; the source's whole-index admission
		// already bounds it. No original row or candidate is dropped.
		if additionalBytes >= limit {
			if err := c.insertWithRetry(ctx, rows); err != nil {
				return err
			}
			rows = nil
			additionalBytes = 0
		}
	}
	if len(rows) > 0 {
		return c.insertWithRetry(ctx, rows)
	}
	return nil
}
