// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package cloudflow

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/ctlplne/probectl/internal/flow"
)

type azureVNetRecord struct {
	Time              string `json:"time"`
	Version           int    `json:"flowLogVersion"`
	Category          string `json:"category"`
	TargetResourceID  string `json:"targetResourceID"`
	FlowLogResourceID string `json:"flowLogResourceID"`
	ResourceID        string `json:"resourceId"`
	MAC               string `json:"macAddress"`
	FlowRecords       struct {
		Flows []struct {
			Groups []struct {
				Tuples []string `json:"flowTuples"`
			} `json:"flowGroups"`
		} `json:"flows"`
	} `json:"flowRecords"`
}

func emitAzureVNetRecord(raw json.RawMessage, tenantID, agentID string, observed time.Time,
	enqueue func(...flow.Record) error) (int, error) {
	var item azureVNetRecord
	if len(raw) > maxAzureLogRecordBytes || json.Unmarshal(raw, &item) != nil || item.Category != "FlowLogFlowEvent" || item.FlowRecords.Flows == nil {
		return 1, nil
	}
	fields := 13
	switch item.Version {
	case 2, 4:
	case 5:
		fields = 16
	default:
		return 1, nil
	}
	exporter, ok := item.exporter()
	if !ok {
		return 1, nil
	}
	if at, err := parseRFC3339(item.Time); err == nil {
		if nanos := at.UnixNano(); nanos >= 0 && time.Unix(0, nanos).Equal(at) {
			observed = at
		}
	}
	base := flow.Record{TenantID: tenantID, AgentID: agentID, Exporter: exporter,
		Protocol: flow.ProtoAzureVNetFlowLogs, ObservedAt: observed, SamplingRate: 1}
	var bad int
	for _, acl := range item.FlowRecords.Flows {
		for _, group := range acl.Groups {
			for _, tuple := range group.Tuples {
				records, err := parseAzureVNetTuple(tuple, fields, base)
				if err != nil {
					bad++
					continue
				}
				if err := enqueue(records...); err != nil {
					return bad, err
				}
			}
		}
	}
	return bad, nil
}

func (item azureVNetRecord) exporter() (string, bool) {
	resource := strings.TrimSpace(item.TargetResourceID)
	if resource == "" {
		resource = strings.TrimSpace(item.FlowLogResourceID)
	}
	if resource == "" {
		resource = strings.TrimSpace(item.ResourceID)
	}
	resource = strings.ToLower(resource)
	if len(resource) > 1024 || !strings.HasPrefix(resource, "/subscriptions/") ||
		strings.IndexFunc(resource, func(r rune) bool { return r <= 0x20 || r > 0x7e }) >= 0 {
		return "", false
	}
	if item.MAC == "" {
		return "azure:" + resource, true
	}
	var mac [6]byte
	if len(item.MAC) != 2*len(mac) {
		return "", false
	}
	if _, err := hex.Decode(mac[:], []byte(item.MAC)); err != nil {
		return "", false
	}
	return "azure:" + resource + ":" + hex.EncodeToString(mac[:]), true
}

func parseAzureVNetTuple(tuple string, fields int, fwd flow.Record) ([]flow.Record, error) {
	if len(tuple) > 1024 {
		return nil, errors.New("azure vnet tuple exceeds the field budget")
	}
	parts := strings.SplitN(tuple, ",", fields+1)
	if len(parts) != fields || (parts[6] != "I" && parts[6] != "O") {
		return nil, errors.New("azure vnet tuple has an unsupported shape")
	}
	switch parts[7] {
	case "B", "D": // A begin or deny event contributes no delivered-traffic counters.
		return nil, nil
	case "C", "E":
	default:
		return nil, errors.New("azure vnet tuple has an unsupported state")
	}
	at, err := azureVNetTime(parts[0])
	if err != nil {
		return nil, err
	}
	fwd.Start, fwd.End = at, at
	if fwd.SrcAddr, err = parseAddr(parts[1]); err != nil {
		return nil, err
	}
	if fwd.DstAddr, err = parseAddr(parts[2]); err != nil {
		return nil, err
	}
	if fwd.SrcAddr.Zone() != "" || fwd.DstAddr.Zone() != "" {
		return nil, errors.New("azure vnet tuple has a scoped IP address")
	}
	if fwd.SrcPort, err = parsePort(parts[3]); err != nil {
		return nil, err
	}
	if fwd.DstPort, err = parsePort(parts[4]); err != nil {
		return nil, err
	}
	if fwd.Transport, err = parseProtocol(parts[5]); err != nil {
		return nil, err
	}
	return azureVNetDirections(parts[9:13], fwd)
}

func azureVNetDirections(fields []string, fwd flow.Record) ([]flow.Record, error) {
	var counts [4]uint64
	for i, field := range fields {
		if field == "" {
			continue
		}
		value, err := parseUint(field)
		if err != nil {
			return nil, err
		}
		counts[i] = value
	}
	forward := fwd
	forward.Packets, forward.Bytes = counts[0], counts[1]
	reverse := fwd
	reverse.SrcAddr, reverse.DstAddr = fwd.DstAddr, fwd.SrcAddr
	reverse.SrcPort, reverse.DstPort = fwd.DstPort, fwd.SrcPort
	reverse.Packets, reverse.Bytes = counts[2], counts[3]
	var records []flow.Record
	for _, record := range [...]flow.Record{forward, reverse} {
		if record.Packets != 0 || record.Bytes != 0 {
			records = append(records, record)
		}
	}
	return records, nil
}

func azureVNetTime(raw string) (time.Time, error) {
	// Microsoft publishes seconds and milliseconds in different v4 samples.
	// Match their widths and ensure the normalized nanosecond field can hold it.
	if len(raw) != 10 && len(raw) != 13 {
		return time.Time{}, errors.New("azure vnet tuple has an unsupported epoch width")
	}
	unit := time.Second
	if len(raw) == 13 {
		unit = time.Millisecond
	}
	v, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || raw[0] < '1' || raw[0] > '9' || v > math.MaxInt64/int64(unit) {
		return time.Time{}, errors.New("azure vnet tuple epoch is out of range")
	}
	return time.Unix(0, v*int64(unit)).UTC(), nil
}
