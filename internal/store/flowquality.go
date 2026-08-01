// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package store

import (
	"context"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// FlowQualityReceipts is the forced-RLS Postgres current-receipt store.
type FlowQualityReceipts struct {
	pool *pgxpool.Pool
}

func NewFlowQualityReceipts(pool *pgxpool.Pool) *FlowQualityReceipts {
	if pool == nil {
		return nil
	}
	return &FlowQualityReceipts{pool: pool}
}

func (s *FlowQualityReceipts) UpsertQualityReceipt(ctx context.Context, tenant string, receipt flow.QualityReceipt) error {
	if s == nil || s.pool == nil {
		return apierror.Unavailable("flow quality receipts are not available in this deployment")
	}
	if tenant == "" || receipt.TenantID != tenant {
		return apierror.Forbidden("flow quality receipt tenant scope mismatch")
	}
	valid, err := flow.ValidateQualityReceipt(receipt)
	if err != nil {
		return err
	}
	ctx = tenancy.WithTenant(ctx, tenancy.ID(tenant))
	return tenancy.InTenant(ctx, s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		if _, err := sc.Q.Exec(ctx, `
			INSERT INTO flow_ingest_quality_receipts
			       (tenant_id, agent_id, exporter_address, protocol,
			        window_started_at, window_ended_at, last_packet_at,
			        last_valid_record_at, packets_received, records_decoded,
			        decode_error_packets, template_misses,
			        queue_dropped_records, emit_dropped_records,
			        template_state, sampling_state, state, reason, next_action,
			        updated_at)
			VALUES ($1, $2, $3::inet, $4, $5, $6, $7, $8, $9, $10, $11, $12,
			        $13, $14, $15, $16, $17, $18, $19, clock_timestamp())
			ON CONFLICT (tenant_id, agent_id, exporter_address, protocol) DO UPDATE SET
			  window_started_at = EXCLUDED.window_started_at,
			  window_ended_at = EXCLUDED.window_ended_at,
			  last_packet_at = greatest(
			    flow_ingest_quality_receipts.last_packet_at,
			    EXCLUDED.last_packet_at
			  ),
			  last_valid_record_at = CASE
			    WHEN flow_ingest_quality_receipts.last_valid_record_at IS NULL
			      THEN EXCLUDED.last_valid_record_at
			    WHEN EXCLUDED.last_valid_record_at IS NULL
			      THEN flow_ingest_quality_receipts.last_valid_record_at
			    ELSE greatest(
			      flow_ingest_quality_receipts.last_valid_record_at,
			      EXCLUDED.last_valid_record_at
			    )
			  END,
			  packets_received = EXCLUDED.packets_received,
			  records_decoded = EXCLUDED.records_decoded,
			  decode_error_packets = EXCLUDED.decode_error_packets,
			  template_misses = EXCLUDED.template_misses,
			  queue_dropped_records = EXCLUDED.queue_dropped_records,
			  emit_dropped_records = EXCLUDED.emit_dropped_records,
			  template_state = EXCLUDED.template_state,
			  sampling_state = EXCLUDED.sampling_state,
			  state = EXCLUDED.state,
			  reason = EXCLUDED.reason,
			  next_action = EXCLUDED.next_action,
			  updated_at = clock_timestamp()
			WHERE EXCLUDED.window_ended_at >= flow_ingest_quality_receipts.window_ended_at`,
			sc.Tenant.String(), valid.AgentID, valid.ExporterAddress, valid.Protocol,
			valid.WindowStartedAt, valid.WindowEndedAt, valid.LastPacketAt,
			valid.LastValidRecordAt, valid.PacketsReceived, valid.RecordsDecoded,
			valid.DecodeErrorPackets, valid.TemplateMisses,
			valid.QueueDroppedRecords, valid.EmitDroppedRecords,
			valid.TemplateState, valid.SamplingState, valid.State, valid.Reason,
			valid.NextAction); err != nil {
			return mapWriteErr("flow quality receipt", err)
		}
		if _, err := sc.Q.Exec(ctx, `
			DELETE FROM flow_ingest_quality_receipts
			 WHERE tenant_id = $1
			   AND window_ended_at
			       < clock_timestamp() - ($2 * interval '1 second')`,
			sc.Tenant.String(), int64(flow.QualityReceiptRetention/time.Second)); err != nil {
			return err
		}
		_, err := sc.Q.Exec(ctx, `
			DELETE FROM flow_ingest_quality_receipts
			 WHERE tenant_id = $1
			   AND (agent_id, exporter_address, protocol) IN (
			     SELECT agent_id, exporter_address, protocol
			       FROM flow_ingest_quality_receipts
			      WHERE tenant_id = $1
			      ORDER BY window_ended_at DESC, agent_id,
			               exporter_address, protocol
			      OFFSET $2
			   )`,
			sc.Tenant.String(), flow.MaxQualityReceiptsPerTenant)
		return err
	})
}

func (s *FlowQualityReceipts) ListQualityReceipts(ctx context.Context, tenant string, filter flow.QualityFilter) ([]flow.QualityReceipt, bool, error) {
	if s == nil || s.pool == nil {
		return nil, false, apierror.Unavailable("flow quality receipts are not available in this deployment")
	}
	if tenant == "" {
		return nil, false, apierror.Validation("tenant_id is required")
	}
	filter.AgentID = strings.TrimSpace(filter.AgentID)
	filter.Exporter = strings.TrimSpace(filter.Exporter)
	filter.Protocol = strings.ToLower(strings.TrimSpace(filter.Protocol))
	filter.State = strings.ToLower(strings.TrimSpace(filter.State))
	if len(filter.AgentID) > 128 {
		return nil, false, apierror.Validation("agent_id is too long")
	}
	if filter.Exporter != "" {
		exporter, err := flow.NormalizeQualityExporter(filter.Exporter)
		if err != nil {
			return nil, false, err
		}
		filter.Exporter = exporter
	}
	if filter.Protocol != "" && !flow.ValidQualityProtocol(filter.Protocol) {
		return nil, false, apierror.Validation("protocol is not a known flow protocol")
	}
	if filter.State != "" && !flow.ValidQualityState(filter.State) {
		return nil, false, apierror.Validation("state is not a known receipt state")
	}
	limit := filter.Limit
	if limit < 1 {
		limit = 100
	}
	if limit > flow.MaxQualityReceiptRead {
		limit = flow.MaxQualityReceiptRead
	}
	asOf := filter.AsOf.UTC()
	if asOf.IsZero() {
		asOf = time.Now().UTC()
	}
	var out []flow.QualityReceipt
	ctx = tenancy.WithTenant(ctx, tenancy.ID(tenant))
	err := tenancy.InTenant(ctx, s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		rows, err := sc.Q.Query(ctx, `
			SELECT agent_id, host(exporter_address), protocol,
			       window_started_at, window_ended_at, last_packet_at,
			       last_valid_record_at, packets_received, records_decoded,
			       decode_error_packets, template_misses,
			       queue_dropped_records, emit_dropped_records,
			       template_state, sampling_state, state, reason, next_action
			  FROM flow_ingest_quality_receipts
			 WHERE tenant_id = $1
			   AND window_ended_at
			       >= $2::timestamptz - ($3 * interval '1 second')
			   AND ($4 = '' OR agent_id = $4)
			   AND ($5 = '' OR exporter_address = NULLIF($5, '')::inet)
			   AND ($6 = '' OR protocol = $6)
			 ORDER BY window_ended_at DESC, agent_id, exporter_address, protocol
			 LIMIT $7`,
			sc.Tenant.String(), asOf, int64(flow.QualityReceiptRetention/time.Second),
			filter.AgentID, filter.Exporter, filter.Protocol,
			flow.MaxQualityReceiptsPerTenant)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var row flow.QualityReceipt
			row.TenantID = tenant
			if err := rows.Scan(
				&row.AgentID, &row.ExporterAddress, &row.Protocol,
				&row.WindowStartedAt, &row.WindowEndedAt, &row.LastPacketAt,
				&row.LastValidRecordAt, &row.PacketsReceived, &row.RecordsDecoded,
				&row.DecodeErrorPackets, &row.TemplateMisses,
				&row.QueueDroppedRecords, &row.EmitDroppedRecords,
				&row.TemplateState, &row.SamplingState, &row.State, &row.Reason,
				&row.NextAction,
			); err != nil {
				return err
			}
			row = flow.EvaluateQualityState(row, asOf)
			if filter.State == "" || row.State == filter.State {
				out = append(out, row)
			}
		}
		return rows.Err()
	})
	if err != nil {
		return nil, false, err
	}
	truncated := len(out) > limit
	if truncated {
		out = out[:limit]
	}
	return out, truncated, nil
}

var _ flow.QualityStore = (*FlowQualityReceipts)(nil)
