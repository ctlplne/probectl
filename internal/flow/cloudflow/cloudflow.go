// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

// Package cloudflow imports cloud-provider flow logs into probectl's normalized
// flow store. It intentionally does not fetch from AWS, Azure, or GCP APIs:
// operators feed local files/objects that their own cloud export pipeline
// produced, preserving the no-phone-home guardrail.
package cloudflow

import (
	"bufio"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/store/flowstore"
)

type Provider string

const (
	ProviderAWSVPC   Provider = "aws_vpc_flow_logs"
	ProviderAzureNSG Provider = "azure_nsg_flow_logs"
	ProviderGCPVPC   Provider = "gcp_vpc_flow_logs"
)

var (
	ErrNoTenant        = errors.New("cloudflow: tenant_id is required")
	ErrNoStore         = errors.New("cloudflow: flow store is required")
	ErrUnknownProvider = errors.New("cloudflow: unknown provider")
)

// Connector loads already-exported cloud flow-log lines into the tenant-scoped
// flow store. Authentication and object access happen before this layer; this
// layer refuses to trust tenant identity from the payload itself.
type Connector struct {
	store   flowstore.Store
	agentID string
	now     func() time.Time
}

// newConnector builds a local cloud-flow importer. agentID is stamped as the
// collecting agent; when empty, a stable importer id is used.
func newConnector(store flowstore.Store, agentID string) *Connector {
	if agentID == "" {
		agentID = "cloud-flow-importer"
	}
	return &Connector{store: store, agentID: agentID, now: time.Now}
}

// load reads newline-delimited provider records, normalizes them, and inserts
// them into the store. Blank lines and '#' comments are ignored. It reports the
// number of rows inserted and the number of malformed lines skipped (RTP-20).
func (c *Connector) load(ctx context.Context, provider Provider, tenantID string, r io.Reader) (inserted, malformed int, err error) {
	if c == nil || c.store == nil {
		return 0, 0, ErrNoStore
	}
	return scan(ctx, provider, tenantID, c.agentID, r, c.now, func(ctx context.Context, recs []flow.Record) error {
		rows := make([]flowstore.Row, 0, len(recs))
		for i := range recs {
			rows = append(rows, rowFromRecord(recs[i]))
		}
		return c.store.Insert(ctx, rows)
	})
}

// Emit reads cloud flow-log lines and publishes them through the normal flow
// emitter path (`probectl.flow.events` in production). It is the flow-agent
// import mode used for local/exported cloud logs. It reports the number of
// records emitted and the number of malformed lines skipped (RTP-20).
func Emit(ctx context.Context, provider Provider, tenantID, agentID string, r io.Reader, emit flow.Emitter) (inserted, malformed int, err error) {
	if emit == nil {
		return 0, 0, errors.New("cloudflow: emitter is required")
	}
	if agentID == "" {
		agentID = "cloud-flow-importer"
	}
	return scan(ctx, provider, tenantID, agentID, r, time.Now, emit.Emit)
}

type recordSink func(context.Context, []flow.Record) error

func scan(ctx context.Context, provider Provider, tenantID, agentID string, r io.Reader, now func() time.Time, sink recordSink) (inserted, malformed int, err error) {
	if tenantID == "" {
		return 0, 0, ErrNoTenant
	}
	if !validProvider(provider) {
		return 0, 0, fmt.Errorf("%w %q", ErrUnknownProvider, provider)
	}
	if now == nil {
		now = time.Now
	}

	// RTP-20: AWS delivers VPC flow logs to S3 as gzip (.log.gz), so the export
	// an operator feeds us is often compressed. Peek the first two bytes for the
	// gzip magic (0x1f 0x8b) and transparently decompress — Peek does not consume
	// the stream, so an uncompressed export is scanned unchanged. This is content
	// detection, not filename detection, so it works for stdin and any entry path.
	br := bufio.NewReader(r)
	var src io.Reader = br
	if magic, perr := br.Peek(2); perr == nil && magic[0] == 0x1f && magic[1] == 0x8b {
		gz, gerr := gzip.NewReader(br)
		if gerr != nil {
			return 0, 0, fmt.Errorf("cloudflow: %s gzip: %w", provider, gerr)
		}
		defer func() { _ = gz.Close() }()
		src = gz
	}

	scanner := bufio.NewScanner(src)
	scanner.Buffer(make([]byte, 0, 64*1024), 2*1024*1024)

	pending := make([]flow.Record, 0, 256)
	flush := func() error {
		if len(pending) == 0 {
			return nil
		}
		if serr := sink(ctx, pending); serr != nil {
			return serr
		}
		inserted += len(pending)
		pending = pending[:0]
		return nil
	}

	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		recs, derr := decodeLine(provider, tenantID, agentID, line, now().UTC())
		if derr != nil {
			// RTP-20: a single malformed line must not abort the whole import.
			// Aborting discarded every valid line, including ones already buffered
			// in pending but not yet flushed (flush happens only at 1000 records or
			// at a clean end that was never reached). The documented contract is
			// that malformed lines are skipped, so count the bad line and continue
			// — valid lines before and after it still import. A dropped denied flow
			// (ING-41) is recs==nil with derr==nil and is not counted here.
			malformed++
			continue
		}
		pending = append(pending, recs...)
		if len(pending) >= 1000 {
			if ferr := flush(); ferr != nil {
				return inserted, malformed, ferr
			}
		}
	}
	if serr := scanner.Err(); serr != nil {
		return inserted, malformed, fmt.Errorf("cloudflow: read %s: %w", provider, serr)
	}
	if ferr := flush(); ferr != nil {
		return inserted, malformed, ferr
	}
	return inserted, malformed, nil
}

func validProvider(p Provider) bool {
	switch p {
	case ProviderAWSVPC, ProviderAzureNSG, ProviderGCPVPC:
		return true
	default:
		return false
	}
}

func decodeLine(provider Provider, tenantID, agentID, line string, now time.Time) ([]flow.Record, error) {
	switch provider {
	case ProviderAWSVPC:
		return parseAWSVPCLine(tenantID, agentID, line, now)
	case ProviderAzureNSG:
		return parseAzureNSGLine(tenantID, agentID, line, now)
	case ProviderGCPVPC:
		return parseGCPVPCLine(tenantID, agentID, line, now)
	default:
		return nil, fmt.Errorf("%w %q", ErrUnknownProvider, provider)
	}
}

func rowFromRecord(r flow.Record) flowstore.Row {
	p := r.ToProto()
	ts := time.Unix(0, p.GetEndUnixNano()).UTC()
	if p.GetEndUnixNano() == 0 {
		ts = time.Unix(0, p.GetObservedAtUnixNano()).UTC()
	}
	startTS := ts
	if p.GetStartUnixNano() != 0 {
		startTS = time.Unix(0, p.GetStartUnixNano()).UTC()
	}
	if startTS.After(ts) {
		startTS = ts
	}
	return flowstore.Row{
		TenantID:      p.GetTenantId(),
		AgentID:       p.GetAgentId(),
		Exporter:      p.GetExporterAddress(),
		ObsDomain:     p.GetObservationDomain(),
		Protocol:      p.GetFlowProtocol(),
		TS:            ts,
		StartTS:       startTS,
		SrcAddr:       p.GetSourceAddress(),
		DstAddr:       p.GetDestinationAddress(),
		SrcPort:       uint16(p.GetSourcePort()),
		DstPort:       uint16(p.GetDestinationPort()),
		Transport:     p.GetNetworkTransport(),
		NetType:       p.GetNetworkType(),
		InIf:          p.GetInputInterface(),
		OutIf:         p.GetOutputInterface(),
		VLAN:          uint16(p.GetVlan()),
		ToS:           uint8(p.GetTos()),
		TCPFlags:      uint8(p.GetTcpFlags()),
		NextHop:       p.GetNextHop(),
		Bytes:         p.GetBytes(),
		Packets:       p.GetPackets(),
		Sampling:      p.GetSamplingRate(),
		BytesScaled:   p.GetBytesScaled(),
		PacketsScaled: p.GetPacketsScaled(),
		SrcASN:        p.GetSourceAsn(),
		SrcASName:     p.GetSourceAsName(),
		SrcCountry:    p.GetSourceCountry(),
		DstASN:        p.GetDestinationAsn(),
		DstASName:     p.GetDestinationAsName(),
		DstCountry:    p.GetDestinationCountry(),
	}
}

func parseAWSVPCLine(tenantID, agentID, line string, now time.Time) ([]flow.Record, error) {
	fields := strings.Fields(line)
	if len(fields) < 14 {
		return nil, fmt.Errorf("aws vpc flow log needs at least 14 default fields, got %d", len(fields))
	}
	if fields[13] != "OK" {
		return nil, nil
	}
	// Field 12 is the ACCEPT/REJECT action; field 13 is the log-status checked
	// above. A REJECT is a packet the VPC security group/NACL denied — not
	// delivered traffic — so it must never be summed alongside ACCEPT flows.
	// Drop denied rows here.
	//
	// Drop-vs-tag: tagging the row with an action dimension (action=accept|
	// reject) would be richer for observability, but the normalized flow
	// record, the flow store Row, the FlowRecord proto and the ClickHouse
	// partitioning carry no action field, so tagging is a cross-package schema
	// change. This fix is scoped to the cloud importer, so a denied flow is
	// dropped rather than tagged — the accounting is then correct (denied
	// traffic is not counted as delivered) within the one touched package.
	if fields[12] == "REJECT" {
		return nil, nil
	}
	src, err := parseAddr(fields[3])
	if err != nil {
		return nil, err
	}
	dst, err := parseAddr(fields[4])
	if err != nil {
		return nil, err
	}
	srcPort, err := parsePort(fields[5])
	if err != nil {
		return nil, err
	}
	dstPort, err := parsePort(fields[6])
	if err != nil {
		return nil, err
	}
	proto, err := parseProtocol(fields[7])
	if err != nil {
		return nil, err
	}
	packets, err := parseUint(fields[8])
	if err != nil {
		return nil, err
	}
	bytes, err := parseUint(fields[9])
	if err != nil {
		return nil, err
	}
	start, err := parseUnixSeconds(fields[10])
	if err != nil {
		return nil, err
	}
	end, err := parseUnixSeconds(fields[11])
	if err != nil {
		return nil, err
	}
	if end.Before(start) {
		start = end
	}
	return []flow.Record{{
		TenantID:     tenantID,
		AgentID:      agentID,
		Exporter:     "aws:" + fields[2],
		Protocol:     flow.ProtoAWSVPCFlowLogs,
		ObservedAt:   now,
		Start:        start,
		End:          end,
		SrcAddr:      src,
		DstAddr:      dst,
		SrcPort:      srcPort,
		DstPort:      dstPort,
		Transport:    proto,
		Bytes:        bytes,
		Packets:      packets,
		SamplingRate: 1,
	}}, nil
}

type azureEnvelope struct {
	Records []azureRecord `json:"records"`
}

type azureRecord struct {
	Time       string          `json:"time"`
	ResourceID string          `json:"resourceId"`
	Properties azureProperties `json:"properties"`
}

type azureProperties struct {
	Version int             `json:"Version"`
	Flows   []azureRuleFlow `json:"flows"`
}

type azureRuleFlow struct {
	Rule  string         `json:"rule"`
	Flows []azureMACFlow `json:"flows"`
}

type azureMACFlow struct {
	MAC        string   `json:"mac"`
	FlowTuples []string `json:"flowTuples"`
}

func parseAzureNSGLine(tenantID, agentID, line string, now time.Time) ([]flow.Record, error) {
	var env azureEnvelope
	if err := json.Unmarshal([]byte(line), &env); err != nil {
		return nil, err
	}
	if len(env.Records) == 0 {
		var single azureRecord
		if err := json.Unmarshal([]byte(line), &single); err != nil {
			return nil, err
		}
		if single.Properties.Version == 0 && len(single.Properties.Flows) == 0 {
			return nil, errors.New("azure nsg payload contains no records")
		}
		env.Records = []azureRecord{single}
	}

	var out []flow.Record
	for _, rec := range env.Records {
		observed := now
		if t, err := parseRFC3339(rec.Time); err == nil {
			observed = t
		}
		for _, rule := range rec.Properties.Flows {
			_ = rule.Rule
			for _, macFlow := range rule.Flows {
				exporter := "azure:" + rec.ResourceID
				if mac := strings.TrimSpace(macFlow.MAC); mac != "" {
					exporter += ":" + strings.ToLower(mac)
				}
				for _, tuple := range macFlow.FlowTuples {
					record, keep, err := parseAzureTuple(tenantID, agentID, exporter, tuple, observed)
					if err != nil {
						return nil, err
					}
					if !keep {
						continue
					}
					out = append(out, record)
				}
			}
		}
	}
	return out, nil
}

// parseAzureTuple decodes one NSG flow tuple. The bool report is whether the
// tuple should be kept: a denied flow (traffic decision "D") is reported with
// keep=false so the caller skips it. See parseAWSVPCLine for the drop-vs-tag
// rationale — a denied flow is a blocked packet, not delivered traffic, and the
// normalized schema has no action dimension to tag, so denied flows are dropped.
func parseAzureTuple(tenantID, agentID, exporter, tuple string, observed time.Time) (flow.Record, bool, error) {
	parts := strings.Split(tuple, ",")
	if len(parts) < 8 {
		return flow.Record{}, false, fmt.Errorf("azure nsg tuple needs at least 8 fields, got %d", len(parts))
	}
	// Part 7 is the traffic decision: "A" (allow) or "D" (deny). Drop denied
	// flows so they are not counted alongside allowed traffic.
	if strings.EqualFold(strings.TrimSpace(parts[7]), "D") {
		return flow.Record{}, false, nil
	}
	start, err := parseUnixSeconds(parts[0])
	if err != nil {
		return flow.Record{}, false, err
	}
	src, err := parseAddr(parts[1])
	if err != nil {
		return flow.Record{}, false, err
	}
	dst, err := parseAddr(parts[2])
	if err != nil {
		return flow.Record{}, false, err
	}
	srcPort, err := parsePort(parts[3])
	if err != nil {
		return flow.Record{}, false, err
	}
	dstPort, err := parsePort(parts[4])
	if err != nil {
		return flow.Record{}, false, err
	}
	proto, err := parseAzureProtocol(parts[5])
	if err != nil {
		return flow.Record{}, false, err
	}
	packets := parseOptionalTupleUint(parts, 9) + parseOptionalTupleUint(parts, 11)
	bytes := parseOptionalTupleUint(parts, 10) + parseOptionalTupleUint(parts, 12)
	return flow.Record{
		TenantID:     tenantID,
		AgentID:      agentID,
		Exporter:     exporter,
		Protocol:     flow.ProtoAzureNSGFlowLogs,
		ObservedAt:   observed,
		Start:        start,
		End:          start,
		SrcAddr:      src,
		DstAddr:      dst,
		SrcPort:      srcPort,
		DstPort:      dstPort,
		Transport:    proto,
		Bytes:        bytes,
		Packets:      packets,
		SamplingRate: 1,
	}, true, nil
}

type gcpLogEntry struct {
	Timestamp string `json:"timestamp"`
	Resource  struct {
		Type   string            `json:"type"`
		Labels map[string]string `json:"labels"`
	} `json:"resource"`
	JSONPayload struct {
		Connection struct {
			SrcIP    string          `json:"src_ip"`
			DstIP    string          `json:"dest_ip"`
			SrcPort  json.RawMessage `json:"src_port"`
			DstPort  json.RawMessage `json:"dest_port"`
			Protocol json.RawMessage `json:"protocol"`
		} `json:"connection"`
		BytesSent   json.RawMessage `json:"bytes_sent"`
		PacketsSent json.RawMessage `json:"packets_sent"`
		StartTime   string          `json:"start_time"`
		EndTime     string          `json:"end_time"`
	} `json:"jsonPayload"`
}

func parseGCPVPCLine(tenantID, agentID, line string, now time.Time) ([]flow.Record, error) {
	var entry gcpLogEntry
	if err := json.Unmarshal([]byte(line), &entry); err != nil {
		return nil, err
	}
	src, err := parseAddr(entry.JSONPayload.Connection.SrcIP)
	if err != nil {
		return nil, err
	}
	dst, err := parseAddr(entry.JSONPayload.Connection.DstIP)
	if err != nil {
		return nil, err
	}
	srcPort, err := parseJSONPort(entry.JSONPayload.Connection.SrcPort)
	if err != nil {
		return nil, err
	}
	dstPort, err := parseJSONPort(entry.JSONPayload.Connection.DstPort)
	if err != nil {
		return nil, err
	}
	proto, err := parseJSONProtocol(entry.JSONPayload.Connection.Protocol)
	if err != nil {
		return nil, err
	}
	bytes, err := parseJSONUint(entry.JSONPayload.BytesSent)
	if err != nil {
		return nil, err
	}
	packets, err := parseJSONUint(entry.JSONPayload.PacketsSent)
	if err != nil {
		return nil, err
	}
	observed := now
	if t, err := parseRFC3339(entry.Timestamp); err == nil {
		observed = t
	}
	start := observed
	if t, err := parseRFC3339(entry.JSONPayload.StartTime); err == nil {
		start = t
	}
	end := observed
	if t, err := parseRFC3339(entry.JSONPayload.EndTime); err == nil {
		end = t
	}
	if end.Before(start) {
		start = end
	}
	return []flow.Record{{
		TenantID:     tenantID,
		AgentID:      agentID,
		Exporter:     gcpExporter(entry),
		Protocol:     flow.ProtoGCPVPCFlowLogs,
		ObservedAt:   observed,
		Start:        start,
		End:          end,
		SrcAddr:      src,
		DstAddr:      dst,
		SrcPort:      srcPort,
		DstPort:      dstPort,
		Transport:    proto,
		Bytes:        bytes,
		Packets:      packets,
		SamplingRate: 1,
	}}, nil
}

func gcpExporter(entry gcpLogEntry) string {
	for _, key := range []string{"subnetwork_id", "subnetwork_name", "network_name", "project_id"} {
		if v := strings.TrimSpace(entry.Resource.Labels[key]); v != "" {
			return "gcp:" + v
		}
	}
	if entry.Resource.Type != "" {
		return "gcp:" + entry.Resource.Type
	}
	return "gcp:vpc-flow-logs"
}

func parseAddr(s string) (netip.Addr, error) {
	s = strings.TrimSpace(s)
	if s == "" || s == "-" {
		return netip.Addr{}, fmt.Errorf("missing IP address %q", s)
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("parse IP address %q: %w", s, err)
	}
	return addr, nil
}

func parsePort(s string) (uint16, error) {
	s = strings.TrimSpace(s)
	if s == "" || s == "-" {
		return 0, nil
	}
	n, err := parseUint(s)
	if err != nil {
		return 0, err
	}
	if n > 65535 {
		return 0, fmt.Errorf("port %d out of range", n)
	}
	return uint16(n), nil
}

func parseProtocol(s string) (uint8, error) {
	n, err := parseUint(strings.TrimSpace(s))
	if err != nil {
		return 0, err
	}
	if n > 255 {
		return 0, fmt.Errorf("protocol %d out of range", n)
	}
	return uint8(n), nil
}

func parseAzureProtocol(s string) (uint8, error) {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "T", "TCP":
		return 6, nil
	case "U", "UDP":
		return 17, nil
	case "I", "ICMP":
		return 1, nil
	default:
		return parseProtocol(s)
	}
}

// maxUnixSeconds bounds a cloud flow log's timestamp field. Year 9999 is far
// past any retention window and still leaves int64 seconds room to spare.
const maxUnixSeconds = 253402300799 // 9999-12-31T23:59:59Z

// parseUnixSeconds reads an epoch-seconds field from a cloud provider's flow log.
//
// DPR-246: the value is third-party content and §7 guardrail 10 says fetched
// content is untrusted, so the range is checked rather than assumed. Without the
// bound an out-of-range value did not fail — it produced a nonsense timestamp:
// 2^63 became the year 292277026596, and max uint64 (int64 -1) became 1969. Either
// way the record was filed silently outside every retention and query window
// instead of being rejected as malformed.
func parseUnixSeconds(s string) (time.Time, error) {
	n, err := parseUint(strings.TrimSpace(s))
	if err != nil {
		return time.Time{}, err
	}
	if n > maxUnixSeconds {
		return time.Time{}, fmt.Errorf("timestamp %d is out of range (max %d)", n, maxUnixSeconds)
	}
	return time.Unix(int64(n), 0).UTC(), nil
}

func parseRFC3339(s string) (time.Time, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, errors.New("empty timestamp")
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}, err
	}
	return t.UTC(), nil
}

func parseUint(s string) (uint64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, errors.New("empty unsigned integer")
	}
	n, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parse unsigned integer %q: %w", s, err)
	}
	return n, nil
}

func parseOptionalTupleUint(parts []string, idx int) uint64 {
	if idx >= len(parts) {
		return 0
	}
	s := strings.TrimSpace(parts[idx])
	if s == "" || s == "-" {
		return 0
	}
	n, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0
	}
	return n
}

func parseJSONUint(raw json.RawMessage) (uint64, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return 0, nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		if strings.TrimSpace(s) == "" {
			return 0, nil
		}
		return parseUint(s)
	}
	var n uint64
	if err := json.Unmarshal(raw, &n); err == nil {
		return n, nil
	}
	return 0, fmt.Errorf("parse JSON unsigned integer %s", string(raw))
}

func parseJSONPort(raw json.RawMessage) (uint16, error) {
	n, err := parseJSONUint(raw)
	if err != nil {
		return 0, err
	}
	if n > 65535 {
		return 0, fmt.Errorf("port %d out of range", n)
	}
	return uint16(n), nil
}

func parseJSONProtocol(raw json.RawMessage) (uint8, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return 0, nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return parseAzureProtocol(s)
	}
	n, err := parseJSONUint(raw)
	if err != nil {
		return 0, err
	}
	if n > 255 {
		return 0, fmt.Errorf("protocol %d out of range", n)
	}
	return uint8(n), nil
}
