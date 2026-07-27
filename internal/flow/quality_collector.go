// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package flow

import (
	"context"
	"encoding/binary"
	"sort"
	"time"
)

// QualityEmitter is the optional production extension implemented by the bus
// emitter. Keeping it optional preserves small in-memory record emitters.
type QualityEmitter interface {
	EmitQuality(context.Context, []QualityReceipt) error
}

type qualityKey struct {
	exporter string
	protocol string
}

type qualityWindow struct {
	windowStartedAt   time.Time
	lastPacketAt      time.Time
	lastValidRecordAt time.Time

	packetsReceived     uint64
	recordsDecoded      uint64
	decodeErrorPackets  uint64
	templateMisses      uint64
	queueDroppedRecords uint64
	emitDroppedRecords  uint64

	templateState string
	samplingState string
	sawSampled    bool
	sawUnsampled  bool
}

func qualityProtocol(listener string, pkt []byte) string {
	switch listener {
	case "ipfix":
		return ProtoIPFIX
	case "sflow":
		return ProtoSFlow5
	case "netflow":
		if len(pkt) >= 2 {
			switch binary.BigEndian.Uint16(pkt[:2]) {
			case 5:
				return ProtoNetFlow5
			case 9:
				return ProtoNetFlow9
			}
		}
		return "netflow"
	default:
		return "netflow"
	}
}

func templateStateForProtocol(protocol string) string {
	switch protocol {
	case ProtoNetFlow5, ProtoSFlow5:
		return QualityTemplateNotApplicable
	case ProtoNetFlow9, ProtoIPFIX:
		return QualityTemplateLearning
	default:
		return QualityTemplateUnknown
	}
}

func saturatingQualityAdd(current, delta uint64) uint64 {
	if current >= MaxQualityCounter || delta > MaxQualityCounter-current {
		return MaxQualityCounter
	}
	return current + delta
}

func (c *Collector) observeQualityPacket(
	exporter, protocol string,
	at time.Time,
	recs []Record,
	templateMisses int,
	decodeFailed bool,
) qualityKey {
	key := qualityKey{exporter: exporter, protocol: protocol}
	c.qualityMu.Lock()
	defer c.qualityMu.Unlock()
	row := c.quality[key]
	if row == nil {
		if len(c.quality) >= MaxQualityReceiptsPerAgent {
			var oldestKey qualityKey
			var oldestAt time.Time
			first := true
			for candidate, receipt := range c.quality {
				if first || receipt.lastPacketAt.Before(oldestAt) {
					oldestKey, oldestAt, first = candidate, receipt.lastPacketAt, false
				}
			}
			if !first {
				delete(c.quality, oldestKey)
			}
		}
		row = &qualityWindow{
			windowStartedAt: at,
			templateState:   templateStateForProtocol(protocol),
			samplingState:   QualitySamplingUnknown,
		}
		c.quality[key] = row
	}
	row.lastPacketAt = at
	row.packetsReceived = saturatingQualityAdd(row.packetsReceived, 1)
	row.recordsDecoded = saturatingQualityAdd(row.recordsDecoded, uint64(len(recs)))
	if decodeFailed {
		row.decodeErrorPackets = saturatingQualityAdd(row.decodeErrorPackets, 1)
	}
	if templateMisses > 0 {
		row.templateMisses = saturatingQualityAdd(row.templateMisses, uint64(templateMisses))
		row.templateState = QualityTemplateMissing
	} else if len(recs) > 0 && (protocol == ProtoNetFlow9 || protocol == ProtoIPFIX) {
		row.templateState = QualityTemplateReady
	}
	if len(recs) > 0 {
		row.lastValidRecordAt = at
		for _, record := range recs {
			if record.SamplingRate > 1 {
				row.sawSampled = true
			} else {
				row.sawUnsampled = true
			}
		}
		switch {
		case row.sawSampled && row.sawUnsampled:
			row.samplingState = QualitySamplingMixed
		case row.sawSampled:
			row.samplingState = QualitySamplingSampled
		default:
			row.samplingState = QualitySamplingUnsampled
		}
	}
	return key
}

func (c *Collector) observeQualityQueueDrop(key qualityKey) {
	c.qualityMu.Lock()
	defer c.qualityMu.Unlock()
	if row := c.quality[key]; row != nil {
		row.queueDroppedRecords = saturatingQualityAdd(row.queueDroppedRecords, 1)
	}
}

func (c *Collector) observeQualityEmitDrops(batch []Record) {
	counts := map[qualityKey]uint64{}
	for _, record := range batch {
		counts[qualityKey{exporter: record.Exporter, protocol: record.Protocol}]++
	}
	c.qualityMu.Lock()
	defer c.qualityMu.Unlock()
	for key, count := range counts {
		if row := c.quality[key]; row != nil {
			row.emitDroppedRecords = saturatingQualityAdd(row.emitDroppedRecords, count)
		}
	}
}

func receiptFromQualityWindow(c *Collector, key qualityKey, row *qualityWindow, at time.Time) QualityReceipt {
	receipt := QualityReceipt{
		TenantID: c.cfg.TenantID, AgentID: c.cfg.AgentID,
		ExporterAddress: key.exporter, Protocol: key.protocol,
		WindowStartedAt: row.windowStartedAt, WindowEndedAt: at, LastPacketAt: row.lastPacketAt,
		PacketsReceived: row.packetsReceived, RecordsDecoded: row.recordsDecoded,
		DecodeErrorPackets: row.decodeErrorPackets, TemplateMisses: row.templateMisses,
		QueueDroppedRecords: row.queueDroppedRecords, EmitDroppedRecords: row.emitDroppedRecords,
		TemplateState: row.templateState, SamplingState: row.samplingState,
	}
	if !row.lastValidRecordAt.IsZero() {
		last := row.lastValidRecordAt
		receipt.LastValidRecordAt = &last
	}
	return EvaluateQualityState(receipt, at)
}

// QualitySnapshot returns a stable, bounded copy without resetting the active
// observation windows. It exists for diagnostics and focused tests.
func (c *Collector) QualitySnapshot(at time.Time) []QualityReceipt {
	c.qualityMu.Lock()
	defer c.qualityMu.Unlock()
	out := make([]QualityReceipt, 0, len(c.quality))
	for key, row := range c.quality {
		out = append(out, receiptFromQualityWindow(c, key, row, at.UTC()))
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].ExporterAddress != out[j].ExporterAddress {
			return out[i].ExporterAddress < out[j].ExporterAddress
		}
		return out[i].Protocol < out[j].Protocol
	})
	return out
}

func (c *Collector) drainQuality(at time.Time) []QualityReceipt {
	c.qualityMu.Lock()
	defer c.qualityMu.Unlock()
	out := make([]QualityReceipt, 0, len(c.quality))
	for key, row := range c.quality {
		out = append(out, receiptFromQualityWindow(c, key, row, at))
		row.windowStartedAt = at
		row.packetsReceived = 0
		row.recordsDecoded = 0
		row.decodeErrorPackets = 0
		row.templateMisses = 0
		row.queueDroppedRecords = 0
		row.emitDroppedRecords = 0
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].ExporterAddress != out[j].ExporterAddress {
			return out[i].ExporterAddress < out[j].ExporterAddress
		}
		return out[i].Protocol < out[j].Protocol
	})
	return out
}

func (c *Collector) restoreQuality(receipts []QualityReceipt) {
	c.qualityMu.Lock()
	defer c.qualityMu.Unlock()
	for _, receipt := range receipts {
		key := qualityKey{exporter: receipt.ExporterAddress, protocol: receipt.Protocol}
		row := c.quality[key]
		if row == nil {
			continue
		}
		if receipt.WindowStartedAt.Before(row.windowStartedAt) {
			row.windowStartedAt = receipt.WindowStartedAt
		}
		row.packetsReceived = saturatingQualityAdd(row.packetsReceived, receipt.PacketsReceived)
		row.recordsDecoded = saturatingQualityAdd(row.recordsDecoded, receipt.RecordsDecoded)
		row.decodeErrorPackets = saturatingQualityAdd(row.decodeErrorPackets, receipt.DecodeErrorPackets)
		row.templateMisses = saturatingQualityAdd(row.templateMisses, receipt.TemplateMisses)
		row.queueDroppedRecords = saturatingQualityAdd(row.queueDroppedRecords, receipt.QueueDroppedRecords)
		row.emitDroppedRecords = saturatingQualityAdd(row.emitDroppedRecords, receipt.EmitDroppedRecords)
	}
}

func (c *Collector) emitQualityReceipts(ctx context.Context, at time.Time) {
	emitter, ok := c.emit.(QualityEmitter)
	if !ok {
		return
	}
	receipts := c.drainQuality(at)
	if len(receipts) == 0 {
		return
	}
	if err := emitter.EmitQuality(ctx, receipts); err != nil {
		c.restoreQuality(receipts)
		c.stats.QualityEmitErrors.Add(1)
		c.log.Error("flow: quality receipt emit failed",
			"receipts", len(receipts), "error", err.Error())
		return
	}
	c.stats.QualityReceipts.Add(uint64(len(receipts)))
}
