// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package flow

import (
	"context"
	"errors"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	flowv1 "github.com/ctlplne/probectl/internal/gen/probectl/flow/v1"
)

const (
	QualityContractVersion = "probectl.flow-ingest-quality/v1"

	QualityStateHealthy  = "healthy"
	QualityStateDegraded = "degraded"
	QualityStateStale    = "stale"

	QualityReasonReceivingValidRecords = "receiving_valid_records"
	QualityReasonWaitingForTemplates   = "waiting_for_templates"
	QualityReasonTemplateMissing       = "template_missing"
	QualityReasonDecodeErrors          = "decode_errors"
	QualityReasonQueueLoss             = "queue_loss"
	QualityReasonEmitLoss              = "emit_loss"
	QualityReasonNoValidRecords        = "no_valid_records"
	QualityReasonNoRecentPackets       = "no_recent_packets"

	QualityActionContinueMonitoring = "continue_monitoring"
	QualityActionVerifyTemplates    = "verify_exporter_templates"
	QualityActionVerifyProtocol     = "verify_exporter_protocol"
	QualityActionReducePressure     = "reduce_local_ingest_pressure"
	QualityActionVerifyBusDelivery  = "verify_local_bus_delivery"
	QualityActionVerifyExporter     = "verify_exporter_delivery"

	QualityTemplateNotApplicable = "not_applicable"
	QualityTemplateUnknown       = "unknown"
	QualityTemplateLearning      = "learning"
	QualityTemplateReady         = "ready"
	QualityTemplateMissing       = "missing"

	QualitySamplingUnknown   = "unknown"
	QualitySamplingUnsampled = "unsampled"
	QualitySamplingSampled   = "sampled"
	QualitySamplingMixed     = "mixed"

	MaxQualityReceiptsPerAgent         = 1_024
	MaxQualityReceiptsPerTenant        = 4_096
	MaxQualityReceiptRead              = 500
	MaxQualityReceiptBatch             = 1_024
	MaxQualityCounter           uint64 = 1<<63 - 1
	QualityReceiptRetention            = 30 * 24 * time.Hour
	QualityStaleAfter                  = 3 * time.Minute
)

// QualityReceipt is one bounded, current ingest-health summary for an
// ACL-accepted exporter/protocol pair. It contains no raw datagram, decoded
// flow field, credential, rejected source, or free-form error text.
type QualityReceipt struct {
	TenantID          string     `json:"-"`
	AgentID           string     `json:"agent_id"`
	ExporterAddress   string     `json:"exporter_address"`
	Protocol          string     `json:"protocol"`
	WindowStartedAt   time.Time  `json:"window_started_at"`
	WindowEndedAt     time.Time  `json:"window_ended_at"`
	LastPacketAt      time.Time  `json:"last_packet_at"`
	LastValidRecordAt *time.Time `json:"last_valid_record_at"`

	PacketsReceived     uint64 `json:"packets_received"`
	RecordsDecoded      uint64 `json:"records_decoded"`
	DecodeErrorPackets  uint64 `json:"decode_error_packets"`
	TemplateMisses      uint64 `json:"template_misses"`
	QueueDroppedRecords uint64 `json:"queue_dropped_records"`
	EmitDroppedRecords  uint64 `json:"emit_dropped_records"`

	TemplateState string `json:"template_state"`
	SamplingState string `json:"sampling_state"`
	State         string `json:"state"`
	Reason        string `json:"reason"`
	NextAction    string `json:"next_action"`
}

// QualityFilter bounds tenant-scoped current-receipt reads.
type QualityFilter struct {
	AgentID  string
	Exporter string
	Protocol string
	State    string
	Limit    int
	// AsOf pins retention, state evaluation, and state filtering to one
	// request-scoped clock. A zero value asks the store to capture UTC now once.
	AsOf time.Time
}

// QualityStore is the tenant-first persistence seam for flow ingest receipts.
type QualityStore interface {
	UpsertQualityReceipt(context.Context, string, QualityReceipt) error
	ListQualityReceipts(context.Context, string, QualityFilter) ([]QualityReceipt, bool, error)
}

var (
	qualityProtocols = map[string]struct{}{
		"netflow": {}, ProtoNetFlow5: {}, ProtoNetFlow9: {}, ProtoIPFIX: {}, ProtoSFlow5: {},
	}
	qualityTemplateStates = map[string]struct{}{
		QualityTemplateNotApplicable: {}, QualityTemplateUnknown: {}, QualityTemplateLearning: {},
		QualityTemplateReady: {}, QualityTemplateMissing: {},
	}
	qualitySamplingStates = map[string]struct{}{
		QualitySamplingUnknown: {}, QualitySamplingUnsampled: {},
		QualitySamplingSampled: {}, QualitySamplingMixed: {},
	}
	qualityStates = map[string]struct{}{
		QualityStateHealthy: {}, QualityStateDegraded: {}, QualityStateStale: {},
	}
)

// EvaluateQualityState applies the stable health/reason/action matrix at asOf.
// API callers re-run it so a receipt becomes stale even if its agent stopped.
func EvaluateQualityState(in QualityReceipt, asOf time.Time) QualityReceipt {
	switch {
	case asOf.Sub(in.LastPacketAt) > QualityStaleAfter:
		in.State, in.Reason, in.NextAction = QualityStateStale, QualityReasonNoRecentPackets, QualityActionVerifyExporter
	case in.EmitDroppedRecords > 0:
		in.State, in.Reason, in.NextAction = QualityStateDegraded, QualityReasonEmitLoss, QualityActionVerifyBusDelivery
	case in.QueueDroppedRecords > 0:
		in.State, in.Reason, in.NextAction = QualityStateDegraded, QualityReasonQueueLoss, QualityActionReducePressure
	case in.DecodeErrorPackets > 0:
		in.State, in.Reason, in.NextAction = QualityStateDegraded, QualityReasonDecodeErrors, QualityActionVerifyProtocol
	case in.TemplateMisses > 0 || in.TemplateState == QualityTemplateMissing:
		in.State, in.Reason, in.NextAction = QualityStateDegraded, QualityReasonTemplateMissing, QualityActionVerifyTemplates
	case in.LastValidRecordAt == nil && in.TemplateState == QualityTemplateLearning:
		in.State, in.Reason, in.NextAction = QualityStateDegraded, QualityReasonWaitingForTemplates, QualityActionVerifyTemplates
	case in.LastValidRecordAt == nil:
		in.State, in.Reason, in.NextAction = QualityStateDegraded, QualityReasonNoValidRecords, QualityActionVerifyProtocol
	default:
		in.State, in.Reason, in.NextAction = QualityStateHealthy, QualityReasonReceivingValidRecords, QualityActionContinueMonitoring
	}
	return in
}

// ValidateQualityReceipt applies the same strict allowlists and bounds at the
// producer, consumer, and storage edges.
func ValidateQualityReceipt(in QualityReceipt) (QualityReceipt, error) {
	in.TenantID = strings.TrimSpace(in.TenantID)
	in.AgentID = strings.TrimSpace(in.AgentID)
	in.ExporterAddress = strings.TrimSpace(in.ExporterAddress)
	in.Protocol = strings.ToLower(strings.TrimSpace(in.Protocol))
	in.TemplateState = strings.ToLower(strings.TrimSpace(in.TemplateState))
	in.SamplingState = strings.ToLower(strings.TrimSpace(in.SamplingState))
	in.State = strings.ToLower(strings.TrimSpace(in.State))
	in.Reason = strings.ToLower(strings.TrimSpace(in.Reason))
	in.NextAction = strings.ToLower(strings.TrimSpace(in.NextAction))
	if in.TenantID == "" || len(in.TenantID) > 128 || in.AgentID == "" || len(in.AgentID) > 128 {
		return QualityReceipt{}, errors.New("flow quality receipt: bounded tenant_id and agent_id are required")
	}
	exporter, err := netip.ParseAddr(in.ExporterAddress)
	if err != nil {
		return QualityReceipt{}, errors.New("flow quality receipt: exporter_address must be an IP address")
	}
	in.ExporterAddress = exporter.Unmap().String()
	if _, ok := qualityProtocols[in.Protocol]; !ok {
		return QualityReceipt{}, errors.New("flow quality receipt: invalid protocol")
	}
	if _, ok := qualityTemplateStates[in.TemplateState]; !ok {
		return QualityReceipt{}, errors.New("flow quality receipt: invalid template_state")
	}
	if _, ok := qualitySamplingStates[in.SamplingState]; !ok {
		return QualityReceipt{}, errors.New("flow quality receipt: invalid sampling_state")
	}
	if _, ok := qualityStates[in.State]; !ok {
		return QualityReceipt{}, errors.New("flow quality receipt: invalid state")
	}
	if in.WindowStartedAt.IsZero() || in.WindowEndedAt.IsZero() || in.LastPacketAt.IsZero() {
		return QualityReceipt{}, errors.New("flow quality receipt: observation window and last_packet_at are required")
	}
	in.WindowStartedAt = in.WindowStartedAt.UTC()
	in.WindowEndedAt = in.WindowEndedAt.UTC()
	in.LastPacketAt = in.LastPacketAt.UTC()
	if in.WindowStartedAt.After(in.WindowEndedAt) || in.WindowEndedAt.Sub(in.WindowStartedAt) > 24*time.Hour ||
		in.LastPacketAt.After(in.WindowEndedAt) {
		return QualityReceipt{}, errors.New("flow quality receipt: invalid observation times")
	}
	if in.LastValidRecordAt != nil {
		at := in.LastValidRecordAt.UTC()
		if at.IsZero() || at.After(in.LastPacketAt) {
			return QualityReceipt{}, errors.New("flow quality receipt: invalid last_valid_record_at")
		}
		in.LastValidRecordAt = &at
	}
	for _, counter := range []uint64{
		in.PacketsReceived, in.RecordsDecoded, in.DecodeErrorPackets, in.TemplateMisses,
		in.QueueDroppedRecords, in.EmitDroppedRecords,
	} {
		if counter > MaxQualityCounter {
			return QualityReceipt{}, errors.New("flow quality receipt: counter is out of bounds")
		}
	}
	if in.RecordsDecoded > 0 && in.LastValidRecordAt == nil {
		return QualityReceipt{}, errors.New("flow quality receipt: decoded records require last_valid_record_at")
	}
	switch in.Protocol {
	case ProtoNetFlow5, ProtoSFlow5:
		if in.TemplateState != QualityTemplateNotApplicable {
			return QualityReceipt{}, errors.New("flow quality receipt: protocol has no templates")
		}
	case ProtoNetFlow9, ProtoIPFIX:
		if in.TemplateState == QualityTemplateNotApplicable || in.TemplateState == QualityTemplateUnknown {
			return QualityReceipt{}, errors.New("flow quality receipt: template protocol requires explicit template state")
		}
	}
	expected := EvaluateQualityState(in, in.WindowEndedAt)
	if in.State != expected.State || in.Reason != expected.Reason || in.NextAction != expected.NextAction {
		return QualityReceipt{}, errors.New("flow quality receipt: state, reason, and next_action are inconsistent")
	}
	return in, nil
}

// ValidQualityState reports whether state is a stable wire value.
func ValidQualityState(state string) bool {
	_, ok := qualityStates[strings.ToLower(strings.TrimSpace(state))]
	return ok
}

// ValidQualityProtocol reports whether protocol is a stable receipt identity.
func ValidQualityProtocol(protocol string) bool {
	_, ok := qualityProtocols[strings.ToLower(strings.TrimSpace(protocol))]
	return ok
}

// NormalizeQualityExporter validates and canonicalizes an exporter IP.
func NormalizeQualityExporter(exporter string) (string, error) {
	addr, err := netip.ParseAddr(strings.TrimSpace(exporter))
	if err != nil {
		return "", errors.New("flow quality receipts: exporter must be an IP address")
	}
	return addr.Unmap().String(), nil
}

func (r QualityReceipt) ToProto() *flowv1.FlowIngestQualityReceipt {
	out := &flowv1.FlowIngestQualityReceipt{
		TenantId: r.TenantID, AgentId: r.AgentID, ExporterAddress: r.ExporterAddress,
		FlowProtocol: r.Protocol, WindowStartedAtUnixNano: r.WindowStartedAt.UnixNano(),
		WindowEndedAtUnixNano: r.WindowEndedAt.UnixNano(), LastPacketAtUnixNano: r.LastPacketAt.UnixNano(),
		PacketsReceived: r.PacketsReceived, RecordsDecoded: r.RecordsDecoded,
		DecodeErrorPackets: r.DecodeErrorPackets, TemplateMisses: r.TemplateMisses,
		QueueDroppedRecords: r.QueueDroppedRecords, EmitDroppedRecords: r.EmitDroppedRecords,
		TemplateState: r.TemplateState, SamplingState: r.SamplingState,
		State: r.State, Reason: r.Reason, NextAction: r.NextAction,
	}
	if r.LastValidRecordAt != nil {
		out.LastValidRecordAtUnixNano = r.LastValidRecordAt.UnixNano()
	}
	return out
}

func QualityReceiptFromProto(in *flowv1.FlowIngestQualityReceipt) QualityReceipt {
	if in == nil {
		return QualityReceipt{}
	}
	out := QualityReceipt{
		TenantID: in.GetTenantId(), AgentID: in.GetAgentId(), ExporterAddress: in.GetExporterAddress(),
		Protocol: in.GetFlowProtocol(), WindowStartedAt: time.Unix(0, in.GetWindowStartedAtUnixNano()),
		WindowEndedAt:   time.Unix(0, in.GetWindowEndedAtUnixNano()),
		LastPacketAt:    time.Unix(0, in.GetLastPacketAtUnixNano()),
		PacketsReceived: in.GetPacketsReceived(), RecordsDecoded: in.GetRecordsDecoded(),
		DecodeErrorPackets: in.GetDecodeErrorPackets(), TemplateMisses: in.GetTemplateMisses(),
		QueueDroppedRecords: in.GetQueueDroppedRecords(), EmitDroppedRecords: in.GetEmitDroppedRecords(),
		TemplateState: in.GetTemplateState(), SamplingState: in.GetSamplingState(),
		State: in.GetState(), Reason: in.GetReason(), NextAction: in.GetNextAction(),
	}
	if in.GetLastValidRecordAtUnixNano() != 0 {
		at := time.Unix(0, in.GetLastValidRecordAtUnixNano()).UTC()
		out.LastValidRecordAt = &at
	}
	return out
}

// MemoryQualityStore is the bounded tenant-keyed lightweight/test store.
type MemoryQualityStore struct {
	mu   sync.RWMutex
	rows map[string]map[string]QualityReceipt
}

func NewMemoryQualityStore() *MemoryQualityStore {
	return &MemoryQualityStore{rows: map[string]map[string]QualityReceipt{}}
}

func qualityReceiptKey(row QualityReceipt) string {
	return row.AgentID + "\x00" + row.ExporterAddress + "\x00" + row.Protocol
}

func (m *MemoryQualityStore) UpsertQualityReceipt(_ context.Context, tenant string, receipt QualityReceipt) error {
	if tenant == "" || receipt.TenantID != tenant {
		return errors.New("flow quality receipts: tenant scope mismatch")
	}
	valid, err := ValidateQualityReceipt(receipt)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.rows[tenant] == nil {
		m.rows[tenant] = map[string]QualityReceipt{}
	}
	key := qualityReceiptKey(valid)
	if current, ok := m.rows[tenant][key]; ok && valid.WindowEndedAt.Before(current.WindowEndedAt) {
		return nil
	}
	m.rows[tenant][key] = valid
	type keyed struct {
		key string
		row QualityReceipt
	}
	all := make([]keyed, 0, len(m.rows[tenant]))
	for rowKey, row := range m.rows[tenant] {
		all = append(all, keyed{key: rowKey, row: row})
	}
	sort.Slice(all, func(i, j int) bool {
		if !all[i].row.WindowEndedAt.Equal(all[j].row.WindowEndedAt) {
			return all[i].row.WindowEndedAt.After(all[j].row.WindowEndedAt)
		}
		return all[i].key < all[j].key
	})
	for _, stale := range all[min(len(all), MaxQualityReceiptsPerTenant):] {
		delete(m.rows[tenant], stale.key)
	}
	return nil
}

func (m *MemoryQualityStore) ListQualityReceipts(_ context.Context, tenant string, filter QualityFilter) ([]QualityReceipt, bool, error) {
	if tenant == "" {
		return nil, false, errors.New("flow quality receipts: tenant_id is required")
	}
	filter.AgentID = strings.TrimSpace(filter.AgentID)
	filter.Exporter = strings.TrimSpace(filter.Exporter)
	filter.Protocol = strings.ToLower(strings.TrimSpace(filter.Protocol))
	filter.State = strings.ToLower(strings.TrimSpace(filter.State))
	if len(filter.AgentID) > 128 {
		return nil, false, errors.New("flow quality receipts: invalid agent_id")
	}
	if filter.Exporter != "" {
		exporter, err := NormalizeQualityExporter(filter.Exporter)
		if err != nil {
			return nil, false, err
		}
		filter.Exporter = exporter
	}
	if filter.Protocol != "" && !ValidQualityProtocol(filter.Protocol) {
		return nil, false, errors.New("flow quality receipts: invalid protocol")
	}
	if filter.State != "" && !ValidQualityState(filter.State) {
		return nil, false, errors.New("flow quality receipts: invalid state")
	}
	limit := filter.Limit
	if limit < 1 {
		limit = 100
	}
	if limit > MaxQualityReceiptRead {
		limit = MaxQualityReceiptRead
	}
	asOf := filter.AsOf.UTC()
	if asOf.IsZero() {
		asOf = time.Now().UTC()
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]QualityReceipt, 0, len(m.rows[tenant]))
	retainAfter := asOf.Add(-QualityReceiptRetention)
	for _, row := range m.rows[tenant] {
		if row.WindowEndedAt.Before(retainAfter) {
			continue
		}
		row = EvaluateQualityState(row, asOf)
		if filter.AgentID != "" && row.AgentID != filter.AgentID ||
			filter.Exporter != "" && row.ExporterAddress != filter.Exporter ||
			filter.Protocol != "" && row.Protocol != filter.Protocol ||
			filter.State != "" && row.State != filter.State {
			continue
		}
		out = append(out, row)
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].WindowEndedAt.Equal(out[j].WindowEndedAt) {
			return out[i].WindowEndedAt.After(out[j].WindowEndedAt)
		}
		return qualityReceiptKey(out[i]) < qualityReceiptKey(out[j])
	})
	truncated := len(out) > limit
	if truncated {
		out = out[:limit]
	}
	return out, truncated, nil
}

var _ QualityStore = (*MemoryQualityStore)(nil)
